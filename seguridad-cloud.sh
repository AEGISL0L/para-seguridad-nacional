#!/bin/bash
# ============================================================
# SEGURIDAD CLOUD - Linux Multi-Distro
# Modulo 52 - Securizar Suite
# ============================================================
# Secciones:
#   S1  - Deteccion de entorno cloud
#   S2  - Seguridad del servicio de metadatos (IMDS)
#   S3  - Auditoria IAM y permisos cloud
#   S4  - Hardening de seguridad de red cloud
#   S5  - Cifrado de volumenes y almacenamiento
#   S6  - Logging y monitoreo cloud
#   S7  - Evaluacion de postura de seguridad cloud
#   S8  - Proteccion contra exfiltracion cloud
#   S9  - Hardening de contenedores en cloud
#   S10 - Auditoria integral de seguridad cloud
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/securizar-common.sh"

require_root
securizar_setup_traps

# ── Pre-check: detectar secciones ya aplicadas ──────────────
_precheck 10
_pc 'check_file_exists /etc/securizar/cloud-provider.conf'
_pc 'check_executable /usr/local/bin/verificar-imds.sh'
_pc 'check_executable /usr/local/bin/auditar-cloud-iam.sh'
_pc 'check_executable /usr/local/bin/auditar-security-groups.sh'
_pc 'check_executable /usr/local/bin/auditar-cifrado-cloud.sh'
_pc 'check_executable /usr/local/bin/verificar-cloud-logging.sh'
_pc 'check_executable /usr/local/bin/evaluar-postura-cloud.sh'
_pc 'check_executable /usr/local/bin/detectar-exfiltracion-cloud.sh'
_pc 'check_executable /usr/local/bin/auditar-contenedores-cloud.sh'
_pc 'check_executable /usr/local/bin/auditoria-seguridad-cloud.sh'
_precheck_result

init_backup "cloud-security"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   MODULO 52 - SEGURIDAD CLOUD                             ║"
echo "║   Deteccion, IMDS, IAM, red, cifrado, logging,            ║"
echo "║   postura, exfiltracion, contenedores, auditoria           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Distro detectada: $DISTRO_NAME ($DISTRO_FAMILY)"

# Directorios base del modulo
mkdir -p /etc/securizar
mkdir -p /var/lib/securizar/cloud
mkdir -p /var/log/securizar

# Variables globales de deteccion cloud
CLOUD_PROVIDER="unknown"
CLOUD_INSTANCE_ID=""
CLOUD_REGION=""
CLOUD_INSTANCE_TYPE=""
CLOUD_ACCOUNT_ID=""
CLOUD_VPC_ID=""
HAS_AWS_CLI=0
HAS_AZ_CLI=0
HAS_GCLOUD_CLI=0

command -v aws &>/dev/null && HAS_AWS_CLI=1
command -v az &>/dev/null && HAS_AZ_CLI=1
command -v gcloud &>/dev/null && HAS_GCLOUD_CLI=1

[[ $HAS_AWS_CLI -eq 1 ]] && log_info "AWS CLI detectado: $(aws --version 2>/dev/null | head -1 || echo 'version desconocida')"
[[ $HAS_AZ_CLI -eq 1 ]] && log_info "Azure CLI detectado: $(az version --output tsv 2>/dev/null | head -1 || echo 'version desconocida')"
[[ $HAS_GCLOUD_CLI -eq 1 ]] && log_info "Google Cloud CLI detectado: $(gcloud version 2>/dev/null | head -1 || echo 'version desconocida')"

# ============================================================
# Funciones auxiliares
# ============================================================

# Acceso a metadatos con timeout corto
_cloud_metadata_check() {
    local url="$1"
    local header="${2:-}"
    local timeout="${3:-2}"
    if [[ -n "$header" ]]; then
        curl -sf -m "$timeout" -H "$header" "$url" 2>/dev/null || true
    else
        curl -sf -m "$timeout" "$url" 2>/dev/null || true
    fi
}

# Detecta hipervisor
_detect_hypervisor() {
    local hv=""
    if [[ -f /sys/hypervisor/type ]]; then
        hv=$(cat /sys/hypervisor/type 2>/dev/null || true)
    fi
    if [[ -z "$hv" ]] && command -v systemd-detect-virt &>/dev/null; then
        hv=$(systemd-detect-virt 2>/dev/null || true)
    fi
    if [[ -z "$hv" ]] && [[ -f /proc/cpuinfo ]]; then
        grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null && hv="vm-detected"
    fi
    echo "${hv:-none}"
}

# ============================================================
# S1: DETECCION DE ENTORNO CLOUD
# ============================================================
log_section "S1: DETECCION DE ENTORNO CLOUD"

echo "Detecta el proveedor cloud y recopila informacion del entorno:"
echo "  - AWS, Azure, GCP, DigitalOcean, Linode, Vultr"
echo "  - Deteccion de hipervisor (KVM, Xen, VMware, VirtualBox)"
echo "  - ID de instancia, region, tipo de instancia"
echo "  - Almacena configuracion en /etc/securizar/cloud-provider.conf"
echo ""

if check_file_exists /etc/securizar/cloud-provider.conf; then
    log_already "Deteccion de entorno cloud (configuracion ya existe)"
elif ask "¿Detectar entorno cloud y recopilar informacion?"; then

    log_info "Iniciando deteccion de entorno cloud..."

    HYPERVISOR=$(_detect_hypervisor)
    log_info "Hipervisor detectado: $HYPERVISOR"

    # --- Deteccion AWS ---
    _detect_aws() {
        local detected=0

        # Metodo 1: UUID del hipervisor
        if [[ -f /sys/hypervisor/uuid ]]; then
            local uuid
            uuid=$(cat /sys/hypervisor/uuid 2>/dev/null || true)
            if [[ "${uuid,,}" == ec2* ]]; then
                log_info "AWS detectado via /sys/hypervisor/uuid"
                detected=1
            fi
        fi

        # Metodo 2: DMI data
        if [[ $detected -eq 0 ]]; then
            local dmi_file dmi_val
            for dmi_file in /sys/class/dmi/id/board_vendor /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/product_name; do
                if [[ -f "$dmi_file" ]]; then
                    dmi_val=$(cat "$dmi_file" 2>/dev/null || true)
                    if [[ "${dmi_val,,}" == *"amazon"* ]] || [[ "${dmi_val,,}" == *"aws"* ]]; then
                        log_info "AWS detectado via DMI: $dmi_file = $dmi_val"
                        detected=1
                        break
                    fi
                fi
            done
        fi

        # Metodo 3: IMDSv2
        if [[ $detected -eq 0 ]]; then
            local imds_token
            imds_token=$(curl -sf -m 2 -X PUT \
                "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
            if [[ -n "$imds_token" ]]; then
                local imds_check
                imds_check=$(_cloud_metadata_check \
                    "http://169.254.169.254/latest/meta-data/ami-id" \
                    "X-aws-ec2-metadata-token: $imds_token")
                if [[ -n "$imds_check" ]]; then
                    log_info "AWS detectado via IMDSv2"
                    detected=1
                fi
            fi
        fi

        # Metodo 4: IMDSv1 fallback
        if [[ $detected -eq 0 ]]; then
            local imds_v1
            imds_v1=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/ami-id")
            if [[ -n "$imds_v1" ]]; then
                log_warn "AWS detectado via IMDSv1 (INSEGURO)"
                detected=1
            fi
        fi

        if [[ $detected -eq 1 ]]; then
            CLOUD_PROVIDER="aws"
            local token
            token=$(curl -sf -m 2 -X PUT \
                "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)

            if [[ -n "$token" ]]; then
                local hdr="X-aws-ec2-metadata-token: $token"
                CLOUD_INSTANCE_ID=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/instance-id" "$hdr")
                CLOUD_REGION=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/placement/region" "$hdr")
                CLOUD_INSTANCE_TYPE=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/instance-type" "$hdr")
                local doc
                doc=$(_cloud_metadata_check "http://169.254.169.254/latest/dynamic/instance-identity/document" "$hdr")
                if [[ -n "$doc" ]] && command -v jq &>/dev/null; then
                    CLOUD_ACCOUNT_ID=$(echo "$doc" | jq -r '.accountId // empty' 2>/dev/null || true)
                    CLOUD_VPC_ID=$(echo "$doc" | jq -r '.vpcId // empty' 2>/dev/null || true)
                fi
            else
                CLOUD_INSTANCE_ID=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/instance-id")
                CLOUD_REGION=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/placement/region")
                CLOUD_INSTANCE_TYPE=$(_cloud_metadata_check "http://169.254.169.254/latest/meta-data/instance-type")
            fi
        fi

        return $((1 - detected))
    }

    # --- Deteccion Azure ---
    _detect_azure() {
        local detected=0

        if [[ -f /sys/class/dmi/id/board_vendor ]]; then
            local vendor
            vendor=$(cat /sys/class/dmi/id/board_vendor 2>/dev/null || true)
            if [[ "${vendor,,}" == *"microsoft"* ]]; then
                log_info "Azure detectado via DMI board_vendor: $vendor"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]] && [[ -f /sys/class/dmi/id/sys_vendor ]]; then
            local sysv
            sysv=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
            if [[ "${sysv,,}" == *"microsoft"* ]]; then
                log_info "Azure detectado via DMI sys_vendor: $sysv"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]] && [[ -f /sys/class/dmi/id/chassis_asset_tag ]]; then
            local chassis
            chassis=$(cat /sys/class/dmi/id/chassis_asset_tag 2>/dev/null || true)
            if [[ "$chassis" == "7783-7084-3265-9085-8269-3286-77" ]]; then
                log_info "Azure detectado via chassis_asset_tag"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]]; then
            local imds_resp
            imds_resp=$(_cloud_metadata_check \
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
                "Metadata: true")
            if [[ -n "$imds_resp" ]] && echo "$imds_resp" | grep -q "compute" 2>/dev/null; then
                log_info "Azure detectado via IMDS"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]]; then
            if [[ -d /var/lib/waagent ]] || systemctl is-active walinuxagent &>/dev/null 2>&1; then
                log_info "Azure detectado via walinuxagent"
                detected=1
            fi
        fi

        if [[ $detected -eq 1 ]]; then
            CLOUD_PROVIDER="azure"
            local meta
            meta=$(_cloud_metadata_check \
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
                "Metadata: true")
            if [[ -n "$meta" ]] && command -v jq &>/dev/null; then
                CLOUD_INSTANCE_ID=$(echo "$meta" | jq -r '.compute.vmId // empty' 2>/dev/null || true)
                CLOUD_REGION=$(echo "$meta" | jq -r '.compute.location // empty' 2>/dev/null || true)
                CLOUD_INSTANCE_TYPE=$(echo "$meta" | jq -r '.compute.vmSize // empty' 2>/dev/null || true)
                CLOUD_ACCOUNT_ID=$(echo "$meta" | jq -r '.compute.subscriptionId // empty' 2>/dev/null || true)
            fi
        fi

        return $((1 - detected))
    }

    # --- Deteccion GCP ---
    _detect_gcp() {
        local detected=0

        if [[ -f /sys/class/dmi/id/product_name ]]; then
            local pname
            pname=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
            if [[ "${pname,,}" == *"google"* ]]; then
                log_info "GCP detectado via DMI product_name: $pname"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]] && [[ -f /sys/class/dmi/id/bios_vendor ]]; then
            local bv
            bv=$(cat /sys/class/dmi/id/bios_vendor 2>/dev/null || true)
            if [[ "${bv,,}" == *"google"* ]]; then
                log_info "GCP detectado via DMI bios_vendor: $bv"
                detected=1
            fi
        fi

        if [[ $detected -eq 0 ]]; then
            local gcp_resp
            gcp_resp=$(_cloud_metadata_check \
                "http://metadata.google.internal/computeMetadata/v1/instance/id" \
                "Metadata-Flavor: Google")
            if [[ -n "$gcp_resp" ]]; then
                log_info "GCP detectado via metadata.google.internal"
                detected=1
            fi
        fi

        if [[ $detected -eq 1 ]]; then
            CLOUD_PROVIDER="gcp"
            local hdr="Metadata-Flavor: Google"
            local base="http://metadata.google.internal/computeMetadata/v1"
            CLOUD_INSTANCE_ID=$(_cloud_metadata_check "${base}/instance/id" "$hdr")
            CLOUD_REGION=$(_cloud_metadata_check "${base}/instance/zone" "$hdr")
            CLOUD_INSTANCE_TYPE=$(_cloud_metadata_check "${base}/instance/machine-type" "$hdr")
            CLOUD_ACCOUNT_ID=$(_cloud_metadata_check "${base}/project/project-id" "$hdr")
            # Limpiar zona y machine-type paths
            [[ -n "$CLOUD_REGION" ]] && CLOUD_REGION=$(echo "$CLOUD_REGION" | sed 's|.*/||' || true)
            [[ -n "$CLOUD_INSTANCE_TYPE" ]] && CLOUD_INSTANCE_TYPE=$(echo "$CLOUD_INSTANCE_TYPE" | sed 's|.*/||' || true)
        fi

        return $((1 - detected))
    }

    # --- Deteccion DigitalOcean ---
    _detect_digitalocean() {
        local detected=0
        if [[ -f /sys/class/dmi/id/sys_vendor ]]; then
            local sysv
            sysv=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
            [[ "${sysv,,}" == *"digitalocean"* ]] && { log_info "DigitalOcean detectado via DMI"; detected=1; }
        fi
        if [[ $detected -eq 0 ]]; then
            local do_resp
            do_resp=$(_cloud_metadata_check "http://169.254.169.254/metadata/v1/id")
            [[ -n "$do_resp" ]] && [[ "$do_resp" =~ ^[0-9]+$ ]] && { log_info "DigitalOcean detectado via metadata"; detected=1; }
        fi
        if [[ $detected -eq 1 ]]; then
            CLOUD_PROVIDER="digitalocean"
            CLOUD_INSTANCE_ID=$(_cloud_metadata_check "http://169.254.169.254/metadata/v1/id")
            CLOUD_REGION=$(_cloud_metadata_check "http://169.254.169.254/metadata/v1/region")
        fi
        return $((1 - detected))
    }

    # --- Deteccion Linode ---
    _detect_linode() {
        local detected=0
        if [[ -f /sys/class/dmi/id/product_name ]]; then
            local pname
            pname=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
            [[ "${pname,,}" == *"linode"* ]] && { log_info "Linode detectado via DMI"; detected=1; }
        fi
        if [[ $detected -eq 0 ]] && [[ -f /sys/class/dmi/id/sys_vendor ]]; then
            local sysv
            sysv=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
            { [[ "${sysv,,}" == *"akamai"* ]] || [[ "${sysv,,}" == *"linode"* ]]; } && { log_info "Linode detectado via DMI"; detected=1; }
        fi
        [[ $detected -eq 1 ]] && CLOUD_PROVIDER="linode"
        return $((1 - detected))
    }

    # --- Deteccion Vultr ---
    _detect_vultr() {
        local detected=0
        if [[ -f /sys/class/dmi/id/sys_vendor ]]; then
            local sysv
            sysv=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
            [[ "${sysv,,}" == *"vultr"* ]] && { log_info "Vultr detectado via DMI"; detected=1; }
        fi
        if [[ $detected -eq 0 ]]; then
            local vultr_resp
            vultr_resp=$(_cloud_metadata_check "http://169.254.169.254/v1/instanceid")
            [[ -n "$vultr_resp" ]] && [[ ${#vultr_resp} -gt 5 ]] && { log_info "Vultr detectado via metadata"; detected=1; }
        fi
        if [[ $detected -eq 1 ]]; then
            CLOUD_PROVIDER="vultr"
            CLOUD_INSTANCE_ID=$(_cloud_metadata_check "http://169.254.169.254/v1/instanceid")
            CLOUD_REGION=$(_cloud_metadata_check "http://169.254.169.254/v1/region")
        fi
        return $((1 - detected))
    }

    # --- Ejecutar deteccion ---
    log_info "Probando deteccion de proveedores cloud..."

    if _detect_aws; then
        log_info "Proveedor: AWS"
    elif _detect_azure; then
        log_info "Proveedor: Azure"
    elif _detect_gcp; then
        log_info "Proveedor: GCP"
    elif _detect_digitalocean; then
        log_info "Proveedor: DigitalOcean"
    elif _detect_linode; then
        log_info "Proveedor: Linode"
    elif _detect_vultr; then
        log_info "Proveedor: Vultr"
    else
        log_warn "No se detecto proveedor cloud conocido"
        case "$HYPERVISOR" in
            kvm|qemu)       CLOUD_PROVIDER="kvm-generic"; log_info "Hipervisor KVM/QEMU (posible cloud privado)" ;;
            xen*)           CLOUD_PROVIDER="xen-generic"; log_info "Hipervisor Xen" ;;
            vmware|VMware*) CLOUD_PROVIDER="vmware"; log_info "VMware detectado" ;;
            oracle*)        CLOUD_PROVIDER="oracle"; log_info "Oracle VM" ;;
            microsoft|Hyper-V|hyperv) CLOUD_PROVIDER="hyperv-generic"; log_info "Hyper-V detectado" ;;
            none)           CLOUD_PROVIDER="baremetal"; log_info "Sin hipervisor - hardware fisico" ;;
            *)              CLOUD_PROVIDER="unknown-vm"; log_info "Hipervisor desconocido: $HYPERVISOR" ;;
        esac
    fi

    # Guardar configuracion
    CLOUD_CONF="/etc/securizar/cloud-provider.conf"
    [[ -f "$CLOUD_CONF" ]] && { cp -a "$CLOUD_CONF" "$BACKUP_DIR/"; log_change "Backup" "$CLOUD_CONF"; }

    cat > "$CLOUD_CONF" << EOFCLOUDCONF
# Deteccion de entorno cloud - seguridad-cloud.sh Modulo 52
# Fecha: $(date -Iseconds)
CLOUD_PROVIDER="${CLOUD_PROVIDER}"
CLOUD_INSTANCE_ID="${CLOUD_INSTANCE_ID}"
CLOUD_REGION="${CLOUD_REGION}"
CLOUD_INSTANCE_TYPE="${CLOUD_INSTANCE_TYPE}"
CLOUD_ACCOUNT_ID="${CLOUD_ACCOUNT_ID}"
CLOUD_VPC_ID="${CLOUD_VPC_ID}"
HYPERVISOR="${HYPERVISOR}"
HAS_AWS_CLI=${HAS_AWS_CLI}
HAS_AZ_CLI=${HAS_AZ_CLI}
HAS_GCLOUD_CLI=${HAS_GCLOUD_CLI}
EOFCLOUDCONF

    chmod 600 "$CLOUD_CONF"
    log_change "Creado" "$CLOUD_CONF"

    log_info "Resumen de deteccion cloud:"
    log_info "  Proveedor:  $CLOUD_PROVIDER"
    [[ -n "$CLOUD_INSTANCE_ID" ]] && log_info "  Instancia:  $CLOUD_INSTANCE_ID"
    [[ -n "$CLOUD_REGION" ]] && log_info "  Region:     $CLOUD_REGION"
    [[ -n "$CLOUD_INSTANCE_TYPE" ]] && log_info "  Tipo:       $CLOUD_INSTANCE_TYPE"
    [[ -n "$CLOUD_ACCOUNT_ID" ]] && log_info "  Cuenta:     $CLOUD_ACCOUNT_ID"
    [[ -n "$CLOUD_VPC_ID" ]] && log_info "  VPC:        $CLOUD_VPC_ID"
    log_info "  Hipervisor: $HYPERVISOR"

else
    log_skip "Deteccion de entorno cloud"
    if [[ -f /etc/securizar/cloud-provider.conf ]]; then
        log_info "Cargando configuracion cloud previa..."
        source /etc/securizar/cloud-provider.conf
        log_info "Proveedor cloud: $CLOUD_PROVIDER"
    fi
fi


# ── S1b: Cloud-init hardening ──
log_info "S1b: Verificando seguridad de cloud-init..."

if [[ -d /etc/cloud ]]; then
    if check_executable /usr/local/bin/auditar-cloud-init.sh; then
        log_already "Auditoría cloud-init"
    elif ask "¿Auditar y securizar cloud-init?"; then

        cat > /usr/local/bin/auditar-cloud-init.sh << 'EOFCLOUDINIT'
#!/bin/bash
# Auditoría de seguridad cloud-init
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

echo -e "${BOLD}=== AUDITORÍA CLOUD-INIT ===${NC}"
ISSUES=0

# Verificar que no hay datos sensibles en user-data
if [[ -f /var/lib/cloud/instance/user-data.txt ]]; then
    if grep -qiE 'password|secret|key|token' /var/lib/cloud/instance/user-data.txt 2>/dev/null; then
        echo -e "  ${RED}ALERTA:${NC} user-data contiene posibles credenciales"
        ((ISSUES++))
    else
        echo -e "  ${GREEN}OK${NC} user-data sin credenciales visibles"
    fi
fi

# Verificar permisos de /var/lib/cloud
PERM=$(stat -c %a /var/lib/cloud 2>/dev/null || echo "?")
if [[ "$PERM" != "755" ]] && [[ "$PERM" != "700" ]]; then
    echo -e "  ${YELLOW}!!${NC} /var/lib/cloud permisos: $PERM (recomendado: 755)"
else
    echo -e "  ${GREEN}OK${NC} /var/lib/cloud permisos: $PERM"
fi

# Verificar módulos peligrosos deshabilitados
for mod in phone_home rightscale_userdata chef puppet salt_minion; do
    if grep -rq "^ *- *$mod" /etc/cloud/cloud.cfg /etc/cloud/cloud.cfg.d/ 2>/dev/null; then
        echo -e "  ${YELLOW}!!${NC} Módulo cloud-init activo: $mod"
        ((ISSUES++))
    fi
done

# Verificar que logs no exponen datos
if [[ -f /var/log/cloud-init.log ]]; then
    PERM_LOG=$(stat -c %a /var/log/cloud-init.log 2>/dev/null || echo "?")
    if [[ "$PERM_LOG" != "600" ]] && [[ "$PERM_LOG" != "640" ]]; then
        echo -e "  ${YELLOW}!!${NC} /var/log/cloud-init.log permisos: $PERM_LOG (recomendado: 640)"
    else
        echo -e "  ${GREEN}OK${NC} cloud-init.log permisos: $PERM_LOG"
    fi
fi

echo ""
echo -e "${BOLD}Issues: $ISSUES${NC}"
EOFCLOUDINIT

        chmod 755 /usr/local/bin/auditar-cloud-init.sh
        log_change "Creado" "/usr/local/bin/auditar-cloud-init.sh"

        # Config segura de cloud-init
        mkdir -p /etc/cloud/cloud.cfg.d
        cat > /etc/cloud/cloud.cfg.d/99-securizar-cloudinit.cfg << 'EOFCFG'
# Securizar: hardening de cloud-init
# Deshabilitar módulos potencialmente peligrosos
cloud_final_modules:
  - scripts-vendor
  - scripts-per-once
  - scripts-per-boot
  - scripts-per-instance
  - scripts-user
  - phone-home

# Restringir acceso a datos de instancia
datasource:
  Ec2:
    strict_id: true
EOFCFG

        log_change "Creado" "/etc/cloud/cloud.cfg.d/99-securizar-cloudinit.cfg"
        log_info "Cloud-init securizado"

    else
        log_skip "Auditoría cloud-init"
    fi
else
    log_info "cloud-init no detectado en este sistema"
fi

# ============================================================
# S2: SEGURIDAD DEL SERVICIO DE METADATOS (IMDS)
# ============================================================
log_section "S2: SEGURIDAD DEL SERVICIO DE METADATOS (IMDS)"

echo "Protege el servicio de metadatos de instancia (IMDS):"
echo "  - AWS: Enforce IMDSv2 (bloquear IMDSv1)"
echo "  - Reglas iptables para restringir acceso a metadatos"
echo "  - Bloqueo de ataques SSRF contra endpoint de metadatos"
echo "  - Azure/GCP: Restriccion de acceso IMDS"
echo "  - Script: /usr/local/bin/verificar-imds.sh"
echo ""

if check_executable /usr/local/bin/verificar-imds.sh; then
    log_already "Proteccion IMDS (script verificar-imds.sh ya existe)"
elif ask "¿Aplicar proteccion del servicio de metadatos?"; then

    METADATA_IP="169.254.169.254"

    # --- Reglas iptables ---
    log_info "Configurando reglas de firewall para proteger IMDS..."

    if command -v iptables &>/dev/null; then
        iptables-save > "$BACKUP_DIR/iptables-pre-imds.rules" 2>/dev/null || true
        log_change "Backup" "reglas iptables actuales"

        # Solo root puede acceder al endpoint de metadatos
        if ! iptables -C OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner --uid-owner 0 -j ACCEPT 2>/dev/null; then
            iptables -I OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner --uid-owner 0 -j ACCEPT
            log_change "Aplicado" "iptables: ACCEPT root -> $METADATA_IP:80"
        else
            log_info "Regla iptables ACCEPT root -> IMDS ya existe"
        fi

        # Log intentos bloqueados
        if ! iptables -C OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner ! --uid-owner 0 -j LOG --log-prefix "IMDS_BLOCKED: " --log-level 4 2>/dev/null; then
            iptables -A OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner ! --uid-owner 0 -j LOG --log-prefix "IMDS_BLOCKED: " --log-level 4 2>/dev/null || true
            log_change "Aplicado" "iptables: LOG intentos no-root a IMDS"
        fi

        # DROP no-root
        if ! iptables -C OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner ! --uid-owner 0 -j DROP 2>/dev/null; then
            iptables -A OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner ! --uid-owner 0 -j DROP
            log_change "Aplicado" "iptables: DROP no-root -> IMDS"
        else
            log_info "Regla DROP no-root -> IMDS ya existe"
        fi

        # IPv6 metadata
        if command -v ip6tables &>/dev/null; then
            if ! ip6tables -C OUTPUT -p tcp -d fd00:ec2::254 --dport 80 -m owner ! --uid-owner 0 -j DROP 2>/dev/null; then
                ip6tables -A OUTPUT -p tcp -d fd00:ec2::254 --dport 80 -m owner ! --uid-owner 0 -j DROP 2>/dev/null || true
                log_change "Aplicado" "ip6tables: DROP no-root -> IMDS IPv6"
            fi
        fi

        # Persistir segun distro
        case "$DISTRO_FAMILY" in
            suse)
                mkdir -p /etc/sysconfig
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                log_change "Guardado" "reglas iptables persistentes (suse)"
                ;;
            debian)
                if command -v netfilter-persistent &>/dev/null; then
                    netfilter-persistent save 2>/dev/null || true
                    log_change "Guardado" "reglas iptables (netfilter-persistent)"
                elif [[ -d /etc/iptables ]]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                    log_change "Guardado" "reglas en /etc/iptables/rules.v4"
                fi
                ;;
            rhel)
                mkdir -p /etc/sysconfig
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                log_change "Guardado" "reglas iptables persistentes (rhel)"
                ;;
            arch)
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true
                log_change "Guardado" "reglas en /etc/iptables/iptables.rules"
                ;;
        esac
    else
        log_warn "iptables no disponible, no se pueden aplicar reglas de proteccion IMDS"
    fi

    # --- AWS: Verificar IMDSv2 ---
    if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
        log_info "Verificando enforcement de IMDSv2..."

        if [[ $HAS_AWS_CLI -eq 1 ]] && [[ -n "$CLOUD_INSTANCE_ID" ]]; then
            imds_state=$(aws ec2 describe-instances \
                --instance-ids "$CLOUD_INSTANCE_ID" \
                --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' \
                --output text 2>/dev/null || echo "error")

            if [[ "$imds_state" == "required" ]]; then
                log_info "IMDSv2 forzado (HttpTokens=required)"
            elif [[ "$imds_state" == "optional" ]]; then
                log_warn "IMDSv1 habilitado (HttpTokens=optional) - RIESGO SSRF"
                if ask "¿Forzar IMDSv2 ahora?"; then
                    if aws ec2 modify-instance-metadata-options \
                        --instance-id "$CLOUD_INSTANCE_ID" \
                        --http-tokens required \
                        --http-endpoint enabled 2>/dev/null; then
                        log_change "Aplicado" "IMDSv2 forzado (HttpTokens=required)"
                    else
                        log_error "Error al forzar IMDSv2 - verificar permisos IAM"
                    fi
                else
                    log_skip "Enforcement de IMDSv2"
                fi
            else
                log_warn "No se pudo verificar estado IMDS: $imds_state"
            fi

            # Hop limit
            hop_limit=$(aws ec2 describe-instances \
                --instance-ids "$CLOUD_INSTANCE_ID" \
                --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' \
                --output text 2>/dev/null || echo "error")
            if [[ "$hop_limit" != "error" ]] && [[ "$hop_limit" -gt 1 ]] 2>/dev/null; then
                log_warn "HttpPutResponseHopLimit=$hop_limit (>1) - contenedores pueden acceder a IMDS"
            elif [[ "$hop_limit" == "1" ]]; then
                log_info "HttpPutResponseHopLimit=1 (contenedores aislados)"
            fi
        else
            log_warn "AWS CLI no disponible o instance-id desconocido"
        fi
    fi

    # --- Azure IMDS ---
    if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
        log_info "Azure IMDS: verificando configuracion..."
        azure_imds=$(_cloud_metadata_check \
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
            "Metadata: true")
        if [[ -n "$azure_imds" ]]; then
            log_info "Azure IMDS accesible (requiere header Metadata: true)"
            log_info "Reglas iptables restringen acceso a root"
        fi
    fi

    # --- GCP metadata concealment ---
    if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
        log_info "GCP: verificando seguridad de metadatos..."
        gcp_meta=$(_cloud_metadata_check \
            "http://metadata.google.internal/computeMetadata/v1/instance/id" \
            "Metadata-Flavor: Google")
        [[ -n "$gcp_meta" ]] && log_info "GCP metadata accesible (requiere header Metadata-Flavor)"

        if [[ $HAS_GCLOUD_CLI -eq 1 ]]; then
            gke_concealment=$(gcloud compute instances describe \
                "$(hostname)" \
                --format="value(metadata.items.filter('key:disable-legacy-endpoints'))" \
                2>/dev/null || true)
            if [[ "$gke_concealment" == "true" ]]; then
                log_info "GKE metadata concealment habilitado"
            elif [[ -n "$gke_concealment" ]]; then
                log_warn "GKE metadata concealment no activo"
            fi
        fi
    fi

    # --- Script de verificacion IMDS ---
    log_info "Creando script de verificacion IMDS..."

    cat > /usr/local/bin/verificar-imds.sh << 'EOFIMDS'
#!/bin/bash
# ============================================================
# verificar-imds.sh - Verificacion de seguridad IMDS
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
METADATA_IP="169.254.169.254"

check_result() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d"; ((WARN++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Verificacion de seguridad IMDS - $(date)${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}"
echo ""

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}"
echo ""

# 1. Reglas firewall
echo -e "${BOLD}1. Reglas de firewall IMDS:${NC}"
if command -v iptables &>/dev/null; then
    if iptables -C OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner ! --uid-owner 0 -j DROP 2>/dev/null; then
        check_result "PASS" "Regla DROP para no-root activa"
    else
        check_result "FAIL" "No hay regla DROP no-root para IMDS"
    fi
    if iptables -C OUTPUT -p tcp -d "$METADATA_IP" --dport 80 -m owner --uid-owner 0 -j ACCEPT 2>/dev/null; then
        check_result "PASS" "Regla ACCEPT para root activa"
    else
        check_result "WARN" "No hay regla ACCEPT explicita para root"
    fi
else
    check_result "FAIL" "iptables no disponible"
fi
echo ""

# 2. Test de acceso no privilegiado
echo -e "${BOLD}2. Test de acceso no privilegiado:${NC}"
if id nobody &>/dev/null 2>&1; then
    nobody_check=$(sudo -u nobody curl -sf -m 2 "http://${METADATA_IP}/" 2>/dev/null || true)
    if [[ -n "$nobody_check" ]]; then
        check_result "FAIL" "IMDS accesible desde usuario nobody"
    else
        check_result "PASS" "IMDS NO accesible desde nobody"
    fi
fi
echo ""

# 3. Checks por proveedor
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
    echo -e "${BOLD}3. AWS IMDSv2:${NC}"
    imdsv1_test=$(curl -sf -m 2 "http://${METADATA_IP}/latest/meta-data/" 2>/dev/null || true)
    if [[ -n "$imdsv1_test" ]]; then
        check_result "FAIL" "IMDSv1 habilitado - vulnerable a SSRF"
    else
        check_result "PASS" "IMDSv1 bloqueado"
    fi
    token=$(curl -sf -m 2 -X PUT "http://${METADATA_IP}/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
    if [[ -n "$token" ]]; then
        check_result "PASS" "IMDSv2 funcional"
        if command -v aws &>/dev/null; then
            inst=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $token" \
                "http://${METADATA_IP}/latest/meta-data/instance-id" 2>/dev/null || true)
            if [[ -n "$inst" ]]; then
                hop=$(aws ec2 describe-instances --instance-ids "$inst" \
                    --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' \
                    --output text 2>/dev/null || echo "unknown")
                [[ "$hop" == "1" ]] && check_result "PASS" "HopLimit=1 (contenedores aislados)"
                [[ "$hop" != "unknown" ]] && [[ "$hop" != "1" ]] && check_result "WARN" "HopLimit=$hop (>1)"
            fi
        fi
    fi
elif [[ "$CLOUD_PROVIDER" == "azure" ]]; then
    echo -e "${BOLD}3. Azure IMDS:${NC}"
    az_noheader=$(curl -sf -m 2 "http://${METADATA_IP}/metadata/instance?api-version=2021-02-01" 2>/dev/null || true)
    if [[ -n "$az_noheader" ]]; then
        check_result "FAIL" "IMDS accesible SIN header Metadata: true"
    else
        check_result "PASS" "IMDS requiere header Metadata: true"
    fi
elif [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
    echo -e "${BOLD}3. GCP Metadata:${NC}"
    gcp_noheader=$(curl -sf -m 2 "http://metadata.google.internal/computeMetadata/v1/instance/id" 2>/dev/null || true)
    if [[ -n "$gcp_noheader" ]]; then
        check_result "FAIL" "Metadata accesible SIN header"
    else
        check_result "PASS" "Metadata requiere header Metadata-Flavor"
    fi
fi
echo ""

# 4. Resumen
echo -e "${BOLD}════════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC}"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}"
elif [[ $FAIL -le 1 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}"
fi
EOFIMDS

    chmod +x /usr/local/bin/verificar-imds.sh
    log_change "Creado" "/usr/local/bin/verificar-imds.sh"
    log_change "Permisos" "/usr/local/bin/verificar-imds.sh -> +x"
    log_info "Ejecuta: verificar-imds.sh"

    # ── S2b: IMDS deep protection con nftables ──
    if command -v nft &>/dev/null; then
        log_info "Configurando protección IMDS avanzada con nftables..."
        mkdir -p /etc/nftables.d
        cat > /etc/nftables.d/imds-protection.nft << 'EOFNFT'
# Securizar: IMDS protection via nftables
# Bloquear acceso no-root al endpoint de metadatos
table inet securizar_imds {
    chain output {
        type filter hook output priority 0; policy accept;
        # Solo root puede acceder a metadata
        ip daddr 169.254.169.254 meta skuid != 0 log prefix "SECURIZAR-IMDS-BLOCK: " drop
        ip6 daddr fd00:ec2::254 meta skuid != 0 log prefix "SECURIZAR-IMDS6-BLOCK: " drop
    }
}
EOFNFT
        chmod 644 /etc/nftables.d/imds-protection.nft
        log_change "Creado" "/etc/nftables.d/imds-protection.nft"

        cat > /usr/local/bin/enforcar-imds-hoplimit.sh << 'EOFHOP'
#!/bin/bash
# Enforce hop-limit=1 para IMDS (previene SSRF cross-container)
set -euo pipefail
echo "Verificando hop-limit para IMDS..."
if command -v nft &>/dev/null; then
    nft list ruleset 2>/dev/null | grep -q "securizar_imds" && \
        echo "[OK] nftables IMDS protection activa" || \
        echo "[!!] nftables IMDS protection no cargada - ejecuta: nft -f /etc/nftables.d/imds-protection.nft"
fi
# Verificar que IMDS en AWS usa hop-limit=1 (IMDSv2)
if curl -s --max-time 2 http://169.254.169.254/latest/api/token -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 30" &>/dev/null; then
    echo "[OK] IMDSv2 accesible (token-based)"
elif curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
    echo "[!!] IMDSv1 accesible - RIESGO: configurar IMDSv2 obligatorio"
else
    echo "[--] IMDS no accesible (no cloud o ya bloqueado)"
fi
EOFHOP
        chmod 755 /usr/local/bin/enforcar-imds-hoplimit.sh
        log_change "Creado" "/usr/local/bin/enforcar-imds-hoplimit.sh"
        log_info "Protección IMDS avanzada con nftables configurada"
    fi

else
    log_skip "Seguridad del servicio de metadatos (IMDS)"
fi

# ============================================================
# S3: AUDITORIA IAM Y PERMISOS CLOUD
# ============================================================
log_section "S3: AUDITORIA IAM Y PERMISOS CLOUD"

echo "Audita permisos IAM del entorno cloud:"
echo "  - AWS: Politicas IAM del rol de instancia, permisos excesivos"
echo "  - Azure: Identidad administrada, asignaciones de rol"
echo "  - GCP: Cuenta de servicio, scopes, bindings IAM"
echo "  - Script: /usr/local/bin/auditar-cloud-iam.sh"
echo ""

if check_executable /usr/local/bin/auditar-cloud-iam.sh; then
    log_already "Auditoria IAM cloud (script ya instalado)"
elif ask "¿Crear script de auditoria IAM cloud?"; then

    log_info "Creando script de auditoria IAM cloud..."

    cat > /usr/local/bin/auditar-cloud-iam.sh << 'EOFIAM'
#!/bin/bash
# ============================================================
# auditar-cloud-iam.sh - Auditoria de permisos IAM cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/iam-audit-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Auditoria IAM Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── AWS IAM ──────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
    echo -e "${BOLD}─── AWS IAM ───${NC}" | tee -a "$REPORT"

    if ! command -v aws &>/dev/null; then
        cr "FAIL" "AWS CLI no instalado"
    else
        # Identidad STS
        echo -e "${BOLD}Identidad STS:${NC}" | tee -a "$REPORT"
        caller=$(aws sts get-caller-identity --output json 2>/dev/null || true)
        sts_arn=""
        if [[ -n "$caller" ]]; then
            sts_arn=$(echo "$caller" | grep -o '"Arn"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || true)
            sts_acct=$(echo "$caller" | grep -o '"Account"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || true)
            cr "INFO" "ARN: $sts_arn"
            cr "INFO" "Cuenta: $sts_acct"
        else
            cr "WARN" "No se pudo obtener identidad STS"
        fi
        echo "" | tee -a "$REPORT"

        # Rol de instancia
        echo -e "${BOLD}Rol de instancia:${NC}" | tee -a "$REPORT"
        token=$(curl -sf -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
        inst_profile=""
        if [[ -n "$token" ]]; then
            inst_profile=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $token" \
                "http://169.254.169.254/latest/meta-data/iam/info" 2>/dev/null || true)
        fi
        if [[ -n "$inst_profile" ]] && echo "$inst_profile" | grep -q "InstanceProfileArn" 2>/dev/null; then
            profile_arn=$(echo "$inst_profile" | grep -o '"InstanceProfileArn"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || true)
            cr "PASS" "Instancia tiene rol IAM: $profile_arn"
        else
            cr "WARN" "Instancia sin rol IAM"
        fi
        echo "" | tee -a "$REPORT"

        # Politicas adjuntas
        echo -e "${BOLD}Politicas adjuntas:${NC}" | tee -a "$REPORT"
        if [[ -n "$sts_arn" ]]; then
            role_name=$(echo "$sts_arn" | sed 's|.*role/||; s|/.*||' || true)
            if [[ -n "$role_name" ]] && [[ "$role_name" != "$sts_arn" ]]; then
                # Managed policies
                managed=$(aws iam list-attached-role-policies --role-name "$role_name" --output json 2>/dev/null || true)
                if [[ -n "$managed" ]]; then
                    while IFS= read -r pname; do
                        [[ -z "$pname" ]] && continue
                        pname=$(echo "$pname" | tr -d '"' | xargs)
                        if [[ "$pname" == "AdministratorAccess" ]] || [[ "$pname" == "PowerUserAccess" ]]; then
                            cr "FAIL" "Politica excesiva: $pname"
                        elif [[ "$pname" == *"FullAccess"* ]]; then
                            cr "WARN" "Politica amplia: $pname"
                        else
                            cr "PASS" "Politica: $pname"
                        fi
                    done < <(echo "$managed" | grep '"PolicyName"' | cut -d'"' -f4)
                fi

                # Inline policies
                inline=$(aws iam list-role-policies --role-name "$role_name" \
                    --query 'PolicyNames[]' --output text 2>/dev/null || true)
                for pname in $inline; do
                    doc=$(aws iam get-role-policy --role-name "$role_name" \
                        --policy-name "$pname" --output json 2>/dev/null || true)
                    if [[ -n "$doc" ]]; then
                        if echo "$doc" | grep -q '"Action".*"\*"' 2>/dev/null; then
                            if echo "$doc" | grep -q '"Resource".*"\*"' 2>/dev/null; then
                                cr "FAIL" "Inline '$pname' tiene *:* (CRITICO)"
                            else
                                cr "WARN" "Inline '$pname' tiene Action:*"
                            fi
                        else
                            cr "PASS" "Inline: $pname"
                        fi
                    fi
                done
            fi
        fi
        echo "" | tee -a "$REPORT"

        # Credenciales STS
        echo -e "${BOLD}Credenciales STS:${NC}" | tee -a "$REPORT"
        cred_role=""
        [[ -n "$token" ]] && cred_role=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $token" \
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
        if [[ -n "$cred_role" ]]; then
            cr "PASS" "Credenciales temporales STS (rol: $cred_role)"
        else
            cr "WARN" "No se detectaron credenciales STS de rol"
        fi
    fi
fi

# ── Azure IAM ────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
    echo -e "${BOLD}─── Azure IAM ───${NC}" | tee -a "$REPORT"

    if ! command -v az &>/dev/null; then
        cr "FAIL" "Azure CLI no instalado"
    else
        msi=$(curl -sf -m 5 \
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
            -H "Metadata: true" 2>/dev/null || true)
        if [[ -n "$msi" ]]; then
            cr "PASS" "Identidad administrada activa"
        else
            cr "WARN" "Identidad administrada no disponible"
        fi

        az_acct=$(az account show --output json 2>/dev/null || true)
        if [[ -n "$az_acct" ]]; then
            az_sub=$(echo "$az_acct" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4 || true)
            cr "INFO" "Suscripcion: $az_sub"
            roles=$(az role assignment list --output json 2>/dev/null || true)
            if [[ -n "$roles" ]]; then
                echo "$roles" | grep -q '"Owner"' 2>/dev/null && cr "WARN" "Asignaciones con rol Owner"
                echo "$roles" | grep -q '"Contributor"' 2>/dev/null && cr "WARN" "Asignaciones con rol Contributor"
            fi
        else
            cr "WARN" "Azure CLI no autenticado"
        fi
    fi
fi

# ── GCP IAM ──────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
    echo -e "${BOLD}─── GCP IAM ───${NC}" | tee -a "$REPORT"

    if ! command -v gcloud &>/dev/null; then
        cr "FAIL" "Google Cloud CLI no instalado"
    else
        sa=$(curl -sf -m 2 -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null || true)
        if [[ -n "$sa" ]]; then
            cr "PASS" "Cuenta de servicio: $sa"
            if [[ "$sa" == *"-compute@developer.gserviceaccount.com" ]]; then
                cr "WARN" "Usando SA por defecto (no recomendado)"
            else
                cr "PASS" "SA personalizada (buena practica)"
            fi
            scopes=$(curl -sf -m 2 -H "Metadata-Flavor: Google" \
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" 2>/dev/null || true)
            if [[ -n "$scopes" ]]; then
                while IFS= read -r scope; do
                    [[ -z "$scope" ]] && continue
                    if [[ "$scope" == *"cloud-platform"* ]]; then
                        cr "WARN" "Scope amplio: $scope"
                    else
                        cr "PASS" "Scope: $scope"
                    fi
                done <<< "$scopes"
            fi
        else
            cr "WARN" "No se detecto cuenta de servicio"
        fi

        proj=$(gcloud config get-value project 2>/dev/null || true)
        if [[ -n "$proj" ]]; then
            iam=$(gcloud projects get-iam-policy "$proj" --format=json 2>/dev/null || true)
            if [[ -n "$iam" ]]; then
                if echo "$iam" | grep -q "allUsers\|allAuthenticatedUsers" 2>/dev/null; then
                    cr "FAIL" "Bindings con acceso publico detectados"
                else
                    cr "PASS" "Sin bindings de acceso publico"
                fi
            fi
        fi
    fi
fi

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]] && [[ $WARN -le 2 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 1 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFIAM

    chmod +x /usr/local/bin/auditar-cloud-iam.sh
    log_change "Creado" "/usr/local/bin/auditar-cloud-iam.sh"
    log_change "Permisos" "/usr/local/bin/auditar-cloud-iam.sh -> +x"

    # Verificar permisos de credenciales locales
    log_info "Verificando permisos de archivos de credenciales cloud..."
    for home_dir in /root /home/*; do
        [[ -d "$home_dir" ]] || continue
        if [[ -f "${home_dir}/.aws/credentials" ]]; then
            cred_perms=$(stat -c '%a' "${home_dir}/.aws/credentials" 2>/dev/null || echo "000")
            if [[ "$cred_perms" != "600" ]]; then
                chmod 600 "${home_dir}/.aws/credentials"
                log_change "Corregido" "permisos ${home_dir}/.aws/credentials -> 600"
            fi
        fi
        if [[ -d "${home_dir}/.config/gcloud" ]]; then
            gcp_perms=$(stat -c '%a' "${home_dir}/.config/gcloud" 2>/dev/null || echo "000")
            if [[ "$gcp_perms" != "700" ]]; then
                chmod 700 "${home_dir}/.config/gcloud"
                log_change "Corregido" "permisos ${home_dir}/.config/gcloud -> 700"
            fi
        fi
        if [[ -d "${home_dir}/.azure" ]]; then
            az_perms=$(stat -c '%a' "${home_dir}/.azure" 2>/dev/null || echo "000")
            if [[ "$az_perms" != "700" ]]; then
                chmod 700 "${home_dir}/.azure"
                log_change "Corregido" "permisos ${home_dir}/.azure -> 700"
            fi
        fi
    done

    log_info "Ejecuta: auditar-cloud-iam.sh"

    # ── S3b: Auditoría de rotación de credenciales cloud ──
    log_info "Verificando rotación de credenciales cloud..."
    cat > /usr/local/bin/auditar-credenciales-cloud.sh << 'EOFCRED'
#!/bin/bash
# Auditoría de credenciales cloud - rotación y exposición
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

echo -e "${BOLD}=== AUDITORÍA DE CREDENCIALES CLOUD ===${NC}"
ISSUES=0

# Buscar credenciales hardcodeadas en archivos comunes
echo -e "\n${BOLD}Credenciales expuestas:${NC}"
for dir in /home /root /etc /opt /var/lib; do
    while IFS= read -r f; do
        echo -e "  ${RED}ALERTA:${NC} Posible credencial en: $f"
        ((ISSUES++))
    done < <(grep -rlE 'AKIA[0-9A-Z]{16}|AWS_SECRET|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS' "$dir" 2>/dev/null | head -20)
done

# Verificar edad de credenciales AWS
echo -e "\n${BOLD}Edad de credenciales:${NC}"
if [[ -f ~/.aws/credentials ]]; then
    AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y ~/.aws/credentials) ) / 86400 ))
    if [[ "$AGE_DAYS" -gt 90 ]]; then
        echo -e "  ${RED}!!${NC} ~/.aws/credentials tiene $AGE_DAYS días (>90)"
        ((ISSUES++))
    else
        echo -e "  ${GREEN}OK${NC} ~/.aws/credentials: $AGE_DAYS días"
    fi
fi

# Verificar variables de entorno con secretos
echo -e "\n${BOLD}Variables de entorno:${NC}"
for var in AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AZURE_CLIENT_SECRET GOOGLE_CREDENTIALS; do
    if printenv "$var" &>/dev/null; then
        echo -e "  ${YELLOW}!!${NC} Variable expuesta: $var"
        ((ISSUES++))
    fi
done

echo -e "\n${BOLD}Issues: $ISSUES${NC}"
[[ $ISSUES -eq 0 ]] && echo -e "${GREEN}Sin problemas de credenciales detectados${NC}"
EOFCRED

    chmod 755 /usr/local/bin/auditar-credenciales-cloud.sh
    log_change "Creado" "/usr/local/bin/auditar-credenciales-cloud.sh"
    log_info "Auditoría de credenciales cloud instalada"

else
    log_skip "Auditoria IAM y permisos cloud"
fi

# ============================================================
# S4: HARDENING DE SEGURIDAD DE RED CLOUD
# ============================================================
log_section "S4: HARDENING DE SEGURIDAD DE RED CLOUD"

echo "Audita la seguridad de red del entorno cloud:"
echo "  - AWS: Security Groups, NACLs, reglas permisivas"
echo "  - Azure: NSG rules, servicios publicos"
echo "  - GCP: Firewall rules, VPC config"
echo "  - VPC Flow Logs habilitados"
echo "  - Script: /usr/local/bin/auditar-security-groups.sh"
echo ""

if check_executable /usr/local/bin/auditar-security-groups.sh; then
    log_already "Auditoria de red cloud (script ya instalado)"
elif ask "¿Crear script de auditoria de seguridad de red cloud?"; then

    log_info "Creando script de auditoria de security groups..."

    cat > /usr/local/bin/auditar-security-groups.sh << 'EOFSG'
#!/bin/bash
# ============================================================
# auditar-security-groups.sh - Auditoria de seguridad de red cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/network-audit-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Auditoria de Red Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

DANGER_PORTS=(22 3389 3306 5432 1433 27017 6379 9200 11211)
DANGER_NAMES=("SSH" "RDP" "MySQL" "PostgreSQL" "MSSQL" "MongoDB" "Redis" "Elasticsearch" "Memcached")

# ── AWS ──────────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    echo -e "${BOLD}─── AWS Security Groups ───${NC}" | tee -a "$REPORT"
    inst="${CLOUD_INSTANCE_ID:-}"
    if [[ -z "$inst" ]]; then
        tk=$(curl -sf -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
        [[ -n "$tk" ]] && inst=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $tk" \
            "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || true)
    fi
    if [[ -n "$inst" ]]; then
        sgs=$(aws ec2 describe-instances --instance-ids "$inst" \
            --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' --output text 2>/dev/null || true)
        for sg in $sgs; do
            echo -e "  ${BOLD}SG: $sg${NC}" | tee -a "$REPORT"
            rules=$(aws ec2 describe-security-groups --group-ids "$sg" --output json 2>/dev/null || true)
            if [[ -n "$rules" ]]; then
                open=$(echo "$rules" | grep -c '0\.0\.0\.0/0' 2>/dev/null || echo "0")
                if [[ "$open" -gt 0 ]]; then
                    cr "WARN" "SG $sg: $open reglas abiertas a internet"
                    for i in "${!DANGER_PORTS[@]}"; do
                        echo "$rules" | grep -q "\"FromPort\": ${DANGER_PORTS[$i]}" 2>/dev/null && \
                            cr "FAIL" "${DANGER_NAMES[$i]} (${DANGER_PORTS[$i]}) abierto en $sg"
                    done
                else
                    cr "PASS" "SG $sg: sin reglas abiertas a internet"
                fi
            fi
        done

        vpc=$(aws ec2 describe-instances --instance-ids "$inst" \
            --query 'Reservations[0].Instances[0].VpcId' --output text 2>/dev/null || true)
        if [[ -n "$vpc" ]] && [[ "$vpc" != "None" ]]; then
            echo "" | tee -a "$REPORT"
            echo -e "${BOLD}NACLs:${NC}" | tee -a "$REPORT"
            nacls=$(aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$vpc" --output json 2>/dev/null || true)
            if [[ -n "$nacls" ]]; then
                nacl_n=$(echo "$nacls" | grep -c '"NetworkAclId"' 2>/dev/null || echo "0")
                cr "INFO" "VPC $vpc tiene $nacl_n NACLs"
            fi

            echo "" | tee -a "$REPORT"
            echo -e "${BOLD}VPC Flow Logs:${NC}" | tee -a "$REPORT"
            fl=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --output json 2>/dev/null || true)
            active=$(echo "$fl" | grep -c '"Active"' 2>/dev/null || echo "0")
            if [[ "$active" -gt 0 ]]; then
                cr "PASS" "VPC Flow Logs activos: $active"
            else
                cr "FAIL" "VPC Flow Logs NO activos para $vpc"
            fi
        fi
    fi
fi

# ── Azure ────────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "azure" ]] && command -v az &>/dev/null; then
    echo -e "${BOLD}─── Azure NSG ───${NC}" | tee -a "$REPORT"
    nsgs=$(az network nsg list --output json 2>/dev/null || true)
    if [[ -n "$nsgs" ]] && [[ "$nsgs" != "[]" ]]; then
        while IFS= read -r nsg_name; do
            [[ -z "$nsg_name" ]] && continue
            if echo "$nsgs" | grep -A 50 "\"name\": \"$nsg_name\"" | grep -q '"sourceAddressPrefix": "\*"' 2>/dev/null; then
                cr "WARN" "NSG '$nsg_name' tiene source *"
            else
                cr "PASS" "NSG '$nsg_name' sin source *"
            fi
        done < <(echo "$nsgs" | grep '"name"' | head -20 | cut -d'"' -f4)
    fi
    nw=$(az network watcher list --output json 2>/dev/null || true)
    if [[ -n "$nw" ]] && [[ "$nw" != "[]" ]]; then
        nw_n=$(echo "$nw" | grep -c '"Succeeded"' 2>/dev/null || echo "0")
        [[ "$nw_n" -gt 0 ]] && cr "PASS" "Network Watcher activo ($nw_n regiones)" || cr "WARN" "Network Watcher no activo"
    fi
fi

# ── GCP ──────────────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "gcp" ]] && command -v gcloud &>/dev/null; then
    echo -e "${BOLD}─── GCP Firewall ───${NC}" | tee -a "$REPORT"
    fw=$(gcloud compute firewall-rules list --format=json 2>/dev/null || true)
    if [[ -n "$fw" ]] && [[ "$fw" != "[]" ]]; then
        fw_n=$(echo "$fw" | grep -c '"name"' 2>/dev/null || echo "0")
        cr "INFO" "Reglas de firewall: $fw_n"
        echo "$fw" | grep -q '"0.0.0.0/0"' 2>/dev/null && cr "WARN" "Reglas con source 0.0.0.0/0"
        echo "$fw" | grep -q '"IPProtocol": "all"' 2>/dev/null && cr "FAIL" "Reglas con protocolo 'all'"

        sub=$(gcloud compute networks subnets list --format=json 2>/dev/null || true)
        if [[ -n "$sub" ]]; then
            fl_on=$(echo "$sub" | grep -c '"enableFlowLogs": true' 2>/dev/null || echo "0")
            [[ "$fl_on" -gt 0 ]] && cr "PASS" "VPC Flow Logs habilitados ($fl_on subnets)" || cr "FAIL" "VPC Flow Logs no habilitados"
        fi
    fi
fi

# ── Servicios locales ────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── Servicios locales expuestos ───${NC}" | tee -a "$REPORT"
if command -v ss &>/dev/null; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "0\.0\.0\.0:" 2>/dev/null; then
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            proc=$(echo "$line" | grep -o 'users:(("[^"]*"' | cut -d'"' -f2 || echo "?")
            case "$port" in
                22)    cr "WARN" "SSH ($port) en 0.0.0.0 ($proc)" ;;
                3306)  cr "FAIL" "MySQL ($port) en 0.0.0.0 ($proc)" ;;
                5432)  cr "FAIL" "PostgreSQL ($port) en 0.0.0.0 ($proc)" ;;
                6379)  cr "FAIL" "Redis ($port) en 0.0.0.0 ($proc)" ;;
                27017) cr "FAIL" "MongoDB ($port) en 0.0.0.0 ($proc)" ;;
                9200)  cr "FAIL" "Elasticsearch ($port) en 0.0.0.0 ($proc)" ;;
                80|443) cr "INFO" "Web ($port) en 0.0.0.0 ($proc)" ;;
                *)     cr "INFO" "Puerto $port en 0.0.0.0 ($proc)" ;;
            esac
        fi
    done < <(ss -tlnp 2>/dev/null || true)
fi

echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 2 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFSG

    chmod +x /usr/local/bin/auditar-security-groups.sh
    log_change "Creado" "/usr/local/bin/auditar-security-groups.sh"
    log_change "Permisos" "/usr/local/bin/auditar-security-groups.sh -> +x"

    # Verificar segmentacion de red
    log_info "Verificando segmentacion de red..."
    if command -v ip &>/dev/null; then
        iface_count=$(ip -o link show 2>/dev/null | grep -cv "lo:" || echo "0")
        log_info "Interfaces de red: $iface_count"
        subnet_count=$(ip -o addr show 2>/dev/null | grep "inet " | grep -cv "127\." || echo "0")
        [[ "$subnet_count" -gt 1 ]] && log_info "Multiples subredes ($subnet_count)" || log_warn "Solo una subred - considerar segmentacion"
    fi

    log_info "Ejecuta: auditar-security-groups.sh"

else
    log_skip "Hardening de seguridad de red cloud"
fi

# ============================================================
# S5: CIFRADO DE VOLUMENES Y ALMACENAMIENTO
# ============================================================
log_section "S5: CIFRADO DE VOLUMENES Y ALMACENAMIENTO"

echo "Verifica el cifrado de volumenes y almacenamiento cloud:"
echo "  - AWS: EBS encryption, S3 bucket encryption"
echo "  - Azure: Disk encryption, Storage account encryption"
echo "  - GCP: Persistent disk encryption, CMEK vs Google-managed"
echo "  - Snapshots/backups sin cifrar"
echo "  - Script: /usr/local/bin/auditar-cifrado-cloud.sh"
echo ""

if check_executable /usr/local/bin/auditar-cifrado-cloud.sh; then
    log_already "Auditoria de cifrado cloud (script ya instalado)"
elif ask "¿Crear script de auditoria de cifrado cloud?"; then

    log_info "Creando script de auditoria de cifrado cloud..."

    cat > /usr/local/bin/auditar-cifrado-cloud.sh << 'EOFCIFRADO'
#!/bin/bash
# ============================================================
# auditar-cifrado-cloud.sh - Auditoria de cifrado cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/encryption-audit-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Auditoria de Cifrado Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── AWS Encryption ───────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    echo -e "${BOLD}─── AWS EBS Encryption ───${NC}" | tee -a "$REPORT"

    # Verificar EBS encryption por defecto
    ebs_default=$(aws ec2 get-ebs-encryption-by-default \
        --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "unknown")
    if [[ "$ebs_default" == "True" ]]; then
        cr "PASS" "EBS encryption por defecto habilitado"
    elif [[ "$ebs_default" == "False" ]]; then
        cr "FAIL" "EBS encryption por defecto NO habilitado"
    else
        cr "WARN" "No se pudo verificar EBS encryption por defecto"
    fi

    # Verificar volumenes no cifrados
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Volumenes EBS:${NC}" | tee -a "$REPORT"
    volumes=$(aws ec2 describe-volumes \
        --query 'Volumes[*].[VolumeId,Encrypted,Size,State]' --output text 2>/dev/null || true)
    if [[ -n "$volumes" ]]; then
        unenc=0; enc=0; total=0
        while IFS=$'\t' read -r vid encrypted size state; do
            [[ -z "$vid" ]] && continue
            ((total++)) || true
            if [[ "$encrypted" == "True" ]]; then
                ((enc++)) || true
            else
                ((unenc++)) || true
                cr "FAIL" "Volumen $vid (${size}GB, $state) NO cifrado"
            fi
        done <<< "$volumes"
        cr "INFO" "Total: $total volumenes, $enc cifrados, $unenc sin cifrar"
    fi

    # S3 bucket encryption
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}S3 Bucket Encryption:${NC}" | tee -a "$REPORT"
    buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null || true)
    if [[ -n "$buckets" ]]; then
        for bucket in $buckets; do
            enc_conf=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || true)
            if [[ -n "$enc_conf" ]]; then
                cr "PASS" "Bucket '$bucket' tiene cifrado configurado"
            else
                cr "FAIL" "Bucket '$bucket' SIN cifrado por defecto"
            fi
        done
    fi

    # Snapshots sin cifrar
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Snapshots EBS:${NC}" | tee -a "$REPORT"
    snaps=$(aws ec2 describe-snapshots --owner-ids self \
        --query 'Snapshots[?Encrypted==`false`].[SnapshotId,VolumeSize]' --output text 2>/dev/null || true)
    if [[ -n "$snaps" ]]; then
        snap_count=$(echo "$snaps" | wc -l)
        cr "FAIL" "$snap_count snapshots sin cifrar"
    else
        cr "PASS" "No se encontraron snapshots sin cifrar"
    fi
fi

# ── Azure Encryption ────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "azure" ]] && command -v az &>/dev/null; then
    echo -e "${BOLD}─── Azure Disk Encryption ───${NC}" | tee -a "$REPORT"

    disks=$(az disk list --query '[*].{name:name,encryption:encryption.type,size:diskSizeGb}' \
        --output json 2>/dev/null || true)
    if [[ -n "$disks" ]] && [[ "$disks" != "[]" ]]; then
        while IFS= read -r dname; do
            [[ -z "$dname" ]] && continue
            enc_type=$(echo "$disks" | grep -A 2 "\"name\": \"$dname\"" | grep "encryption" | cut -d'"' -f4 || echo "unknown")
            if [[ "$enc_type" == "EncryptionAtRestWithPlatformKey" ]] || [[ "$enc_type" == "EncryptionAtRestWithCustomerKey" ]]; then
                cr "PASS" "Disco '$dname' cifrado ($enc_type)"
            else
                cr "WARN" "Disco '$dname' cifrado tipo: $enc_type"
            fi
        done < <(echo "$disks" | grep '"name"' | cut -d'"' -f4)
    fi

    # Storage accounts
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Storage Account Encryption:${NC}" | tee -a "$REPORT"
    sa_list=$(az storage account list \
        --query '[*].{name:name,encryption:encryption.services.blob.enabled}' --output json 2>/dev/null || true)
    if [[ -n "$sa_list" ]] && [[ "$sa_list" != "[]" ]]; then
        while IFS= read -r sa_name; do
            [[ -z "$sa_name" ]] && continue
            cr "PASS" "Storage account '$sa_name' tiene cifrado habilitado"
        done < <(echo "$sa_list" | grep '"name"' | cut -d'"' -f4)
    fi
fi

# ── GCP Encryption ──────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "gcp" ]] && command -v gcloud &>/dev/null; then
    echo -e "${BOLD}─── GCP Disk Encryption ───${NC}" | tee -a "$REPORT"

    gcp_disks=$(gcloud compute disks list --format=json 2>/dev/null || true)
    if [[ -n "$gcp_disks" ]] && [[ "$gcp_disks" != "[]" ]]; then
        while IFS= read -r dname; do
            [[ -z "$dname" ]] && continue
            has_cmek=$(echo "$gcp_disks" | grep -A 10 "\"name\": \"$dname\"" | grep -c "diskEncryptionKey" 2>/dev/null || echo "0")
            if [[ "$has_cmek" -gt 0 ]]; then
                cr "PASS" "Disco '$dname' usa CMEK (customer-managed encryption)"
            else
                cr "INFO" "Disco '$dname' usa Google-managed encryption (por defecto)"
            fi
        done < <(echo "$gcp_disks" | grep '"name"' | cut -d'"' -f4)
    fi

    # GCS buckets
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}GCS Bucket Encryption:${NC}" | tee -a "$REPORT"
    gcs_buckets=$(gcloud storage buckets list --format="value(name)" 2>/dev/null || true)
    if [[ -n "$gcs_buckets" ]]; then
        while IFS= read -r bname; do
            [[ -z "$bname" ]] && continue
            bucket_enc=$(gcloud storage buckets describe "gs://$bname" \
                --format="value(default_kms_key)" 2>/dev/null || true)
            if [[ -n "$bucket_enc" ]]; then
                cr "PASS" "Bucket '$bname' usa CMEK: $bucket_enc"
            else
                cr "INFO" "Bucket '$bname' usa Google-managed encryption"
            fi
        done <<< "$gcs_buckets"
    fi
fi

# ── Cifrado local ────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── Cifrado local ───${NC}" | tee -a "$REPORT"

# Verificar LUKS
if command -v lsblk &>/dev/null; then
    luks_count=$(lsblk -o NAME,TYPE 2>/dev/null | grep -c "crypt" || echo "0")
    if [[ "$luks_count" -gt 0 ]]; then
        cr "PASS" "$luks_count volumenes LUKS detectados"
    else
        cr "INFO" "No se detectaron volumenes LUKS"
    fi
fi

# Verificar dm-crypt
if [[ -d /dev/mapper ]]; then
    mapper_count=$(ls /dev/mapper/ 2>/dev/null | grep -cv "control" || echo "0")
    cr "INFO" "Device-mapper entries: $mapper_count"
fi

# Resumen
echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 2 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFCIFRADO

    chmod +x /usr/local/bin/auditar-cifrado-cloud.sh
    log_change "Creado" "/usr/local/bin/auditar-cifrado-cloud.sh"
    log_change "Permisos" "/usr/local/bin/auditar-cifrado-cloud.sh -> +x"

    # Verificar cifrado local
    log_info "Verificando estado de cifrado local..."
    if command -v lsblk &>/dev/null; then
        luks_count=$(lsblk -o NAME,TYPE 2>/dev/null | grep -c "crypt" || echo "0")
        if [[ "$luks_count" -gt 0 ]]; then
            log_info "$luks_count volumenes cifrados (LUKS) detectados"
        else
            log_warn "No se detectaron volumenes cifrados localmente"
        fi
    fi

    # AWS: Verificar EBS encryption
    if [[ "$CLOUD_PROVIDER" == "aws" ]] && [[ $HAS_AWS_CLI -eq 1 ]]; then
        ebs_default=$(aws ec2 get-ebs-encryption-by-default \
            --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "unknown")
        if [[ "$ebs_default" == "True" ]]; then
            log_info "AWS EBS encryption por defecto: habilitado"
        elif [[ "$ebs_default" == "False" ]]; then
            log_warn "AWS EBS encryption por defecto: NO habilitado"
            if ask "¿Habilitar EBS encryption por defecto?"; then
                if aws ec2 enable-ebs-encryption-by-default 2>/dev/null; then
                    log_change "Aplicado" "EBS encryption por defecto habilitado"
                else
                    log_error "Error al habilitar EBS encryption - verificar permisos"
                fi
            else
                log_skip "EBS encryption por defecto"
            fi
        fi
    fi

    log_info "Ejecuta: auditar-cifrado-cloud.sh"

else
    log_skip "Cifrado de volumenes y almacenamiento"
fi

# ============================================================
# S6: LOGGING Y MONITOREO CLOUD
# ============================================================
log_section "S6: LOGGING Y MONITOREO CLOUD"

echo "Verifica logging y monitoreo del entorno cloud:"
echo "  - AWS: CloudTrail, CloudWatch alarms"
echo "  - Azure: Activity Log, Azure Monitor"
echo "  - GCP: Cloud Audit Logs"
echo "  - Centralizacion de logs"
echo "  - Retencion de logs"
echo "  - Script: /usr/local/bin/verificar-cloud-logging.sh"
echo ""

if check_executable /usr/local/bin/verificar-cloud-logging.sh; then
    log_already "Verificacion de logging cloud (script ya instalado)"
elif ask "¿Crear script de verificacion de logging cloud?"; then

    log_info "Creando script de verificacion de logging cloud..."

    cat > /usr/local/bin/verificar-cloud-logging.sh << 'EOFLOGGING'
#!/bin/bash
# ============================================================
# verificar-cloud-logging.sh - Verificacion de logging cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/cloud-logging-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Verificacion de Logging Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── AWS CloudTrail & CloudWatch ──────────────────────────
if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    echo -e "${BOLD}─── AWS CloudTrail ───${NC}" | tee -a "$REPORT"

    trails=$(aws cloudtrail describe-trails --output json 2>/dev/null || true)
    if [[ -n "$trails" ]]; then
        trail_count=$(echo "$trails" | grep -c '"Name"' 2>/dev/null || echo "0")
        if [[ "$trail_count" -gt 0 ]]; then
            cr "PASS" "$trail_count CloudTrails configurados"

            # Verificar multiregion y log file validation
            while IFS= read -r tname; do
                [[ -z "$tname" ]] && continue
                trail_status=$(aws cloudtrail get-trail-status --name "$tname" --output json 2>/dev/null || true)
                if [[ -n "$trail_status" ]]; then
                    is_logging=$(echo "$trail_status" | grep -o '"IsLogging": [a-z]*' | cut -d' ' -f2 || echo "unknown")
                    if [[ "$is_logging" == "true" ]]; then
                        cr "PASS" "Trail '$tname' esta activo (logging=true)"
                    else
                        cr "FAIL" "Trail '$tname' NO esta activo (logging=$is_logging)"
                    fi
                fi

                # Multiregion
                is_multi=$(echo "$trails" | grep -A 5 "\"Name\": \"$tname\"" | grep -o '"IsMultiRegionTrail": [a-z]*' | cut -d' ' -f2 || echo "unknown")
                if [[ "$is_multi" == "true" ]]; then
                    cr "PASS" "Trail '$tname' es multiregion"
                else
                    cr "WARN" "Trail '$tname' NO es multiregion"
                fi

                # Log file validation
                has_validation=$(echo "$trails" | grep -A 5 "\"Name\": \"$tname\"" | grep -o '"LogFileValidationEnabled": [a-z]*' | cut -d' ' -f2 || echo "unknown")
                if [[ "$has_validation" == "true" ]]; then
                    cr "PASS" "Trail '$tname' tiene log file validation"
                else
                    cr "WARN" "Trail '$tname' sin log file validation"
                fi
            done < <(echo "$trails" | grep '"Name"' | cut -d'"' -f4)
        else
            cr "FAIL" "No hay CloudTrails configurados"
        fi
    fi

    # CloudWatch alarms
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}CloudWatch Alarms:${NC}" | tee -a "$REPORT"
    alarms=$(aws cloudwatch describe-alarms --state-value ALARM --output json 2>/dev/null || true)
    if [[ -n "$alarms" ]]; then
        alarm_count=$(echo "$alarms" | grep -c '"AlarmName"' 2>/dev/null || echo "0")
        if [[ "$alarm_count" -gt 0 ]]; then
            cr "WARN" "$alarm_count alarmas en estado ALARM"
        else
            cr "PASS" "Sin alarmas en estado ALARM"
        fi
    fi
    total_alarms=$(aws cloudwatch describe-alarms --query 'MetricAlarms | length(@)' --output text 2>/dev/null || echo "0")
    cr "INFO" "Total alarmas CloudWatch: $total_alarms"

    # GuardDuty
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}GuardDuty:${NC}" | tee -a "$REPORT"
    gd_detectors=$(aws guardduty list-detectors --output text 2>/dev/null || true)
    if [[ -n "$gd_detectors" ]] && [[ "$gd_detectors" != "DETECTORIDS" ]]; then
        cr "PASS" "GuardDuty habilitado"
    else
        cr "WARN" "GuardDuty no detectado o no habilitado"
    fi
fi

# ── Azure Logging ────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "azure" ]] && command -v az &>/dev/null; then
    echo -e "${BOLD}─── Azure Logging ───${NC}" | tee -a "$REPORT"

    # Activity Log
    echo -e "${BOLD}Activity Log:${NC}" | tee -a "$REPORT"
    diag_settings=$(az monitor diagnostic-settings subscription list --output json 2>/dev/null || true)
    if [[ -n "$diag_settings" ]] && [[ "$diag_settings" != "[]" ]]; then
        cr "PASS" "Diagnostic settings de suscripcion configurados"
    else
        cr "WARN" "Sin diagnostic settings de suscripcion"
    fi

    # Azure Monitor
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Azure Monitor:${NC}" | tee -a "$REPORT"
    alerts=$(az monitor metrics alert list --output json 2>/dev/null || true)
    if [[ -n "$alerts" ]] && [[ "$alerts" != "[]" ]]; then
        alert_n=$(echo "$alerts" | grep -c '"name"' 2>/dev/null || echo "0")
        cr "PASS" "$alert_n alertas de metricas configuradas"
    else
        cr "WARN" "Sin alertas de metricas configuradas"
    fi

    # Log Analytics
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Log Analytics:${NC}" | tee -a "$REPORT"
    workspaces=$(az monitor log-analytics workspace list --output json 2>/dev/null || true)
    if [[ -n "$workspaces" ]] && [[ "$workspaces" != "[]" ]]; then
        ws_n=$(echo "$workspaces" | grep -c '"name"' 2>/dev/null || echo "0")
        cr "PASS" "$ws_n workspaces de Log Analytics"
    else
        cr "WARN" "Sin workspaces de Log Analytics"
    fi
fi

# ── GCP Logging ──────────────────────────────────────────
if [[ "$CLOUD_PROVIDER" == "gcp" ]] && command -v gcloud &>/dev/null; then
    echo -e "${BOLD}─── GCP Cloud Audit Logs ───${NC}" | tee -a "$REPORT"

    proj=$(gcloud config get-value project 2>/dev/null || true)
    if [[ -n "$proj" ]]; then
        # Audit log config
        audit_config=$(gcloud projects get-iam-policy "$proj" \
            --format="json(auditConfigs)" 2>/dev/null || true)
        if echo "$audit_config" | grep -q "auditLogConfigs" 2>/dev/null; then
            cr "PASS" "Audit logging configurado en proyecto $proj"
        else
            cr "FAIL" "Audit logging NO configurado"
        fi

        # Log sinks
        echo "" | tee -a "$REPORT"
        echo -e "${BOLD}Log Sinks:${NC}" | tee -a "$REPORT"
        sinks=$(gcloud logging sinks list --format=json 2>/dev/null || true)
        if [[ -n "$sinks" ]] && [[ "$sinks" != "[]" ]]; then
            sink_n=$(echo "$sinks" | grep -c '"name"' 2>/dev/null || echo "0")
            cr "PASS" "$sink_n log sinks configurados"
        else
            cr "WARN" "Sin log sinks configurados (logs no exportados)"
        fi

        # Log-based metrics
        echo "" | tee -a "$REPORT"
        echo -e "${BOLD}Metricas basadas en logs:${NC}" | tee -a "$REPORT"
        metrics=$(gcloud logging metrics list --format=json 2>/dev/null || true)
        if [[ -n "$metrics" ]] && [[ "$metrics" != "[]" ]]; then
            met_n=$(echo "$metrics" | grep -c '"name"' 2>/dev/null || echo "0")
            cr "PASS" "$met_n metricas basadas en logs"
        else
            cr "WARN" "Sin metricas basadas en logs"
        fi
    fi
fi

# ── Logging local ────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── Logging local ───${NC}" | tee -a "$REPORT"

# journald
if systemctl is-active systemd-journald &>/dev/null 2>&1; then
    cr "PASS" "systemd-journald activo"
    journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[GMK]' | head -1 || echo "?")
    cr "INFO" "Tamano de journal: $journal_size"
else
    cr "WARN" "systemd-journald no activo"
fi

# rsyslog
if systemctl is-active rsyslog &>/dev/null 2>&1; then
    cr "PASS" "rsyslog activo"
else
    cr "INFO" "rsyslog no activo"
fi

# auditd
if systemctl is-active auditd &>/dev/null 2>&1; then
    cr "PASS" "auditd activo"
else
    cr "WARN" "auditd no activo"
fi

echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 1 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFLOGGING

    chmod +x /usr/local/bin/verificar-cloud-logging.sh
    log_change "Creado" "/usr/local/bin/verificar-cloud-logging.sh"
    log_change "Permisos" "/usr/local/bin/verificar-cloud-logging.sh -> +x"

    # Verificacion rapida de logging local
    log_info "Verificando servicios de logging locales..."
    systemctl is-active systemd-journald &>/dev/null 2>&1 && log_info "journald: activo" || log_warn "journald: no activo"
    systemctl is-active rsyslog &>/dev/null 2>&1 && log_info "rsyslog: activo" || log_info "rsyslog: no activo"
    systemctl is-active auditd &>/dev/null 2>&1 && log_info "auditd: activo" || log_warn "auditd: no activo"

    # AWS: Verificar CloudTrail
    if [[ "$CLOUD_PROVIDER" == "aws" ]] && [[ $HAS_AWS_CLI -eq 1 ]]; then
        trails=$(aws cloudtrail describe-trails --query 'trailList | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$trails" -gt 0 ]]; then
            log_info "AWS CloudTrail: $trails trails configurados"
        else
            log_warn "AWS CloudTrail: no se detectaron trails"
        fi
    fi

    log_info "Ejecuta: verificar-cloud-logging.sh"

else
    log_skip "Logging y monitoreo cloud"
fi

# ============================================================
# S7: EVALUACION DE POSTURA DE SEGURIDAD CLOUD
# ============================================================
log_section "S7: EVALUACION DE POSTURA DE SEGURIDAD CLOUD"

echo "Evaluacion comprehensiva de postura de seguridad cloud:"
echo "  - CIS Benchmarks para cloud (AWS CIS, Azure CIS)"
echo "  - Puntuacion por categorias: IAM, Red, Logging, Cifrado"
echo "  - Deteccion de misconfigurations comunes"
echo "  - Prowler (AWS), ScoutSuite (multi-cloud)"
echo "  - Script: /usr/local/bin/evaluar-postura-cloud.sh"
echo ""

if check_executable /usr/local/bin/evaluar-postura-cloud.sh; then
    log_already "Evaluacion de postura cloud (script ya instalado)"
elif ask "¿Crear script de evaluacion de postura cloud?"; then

    log_info "Creando script de evaluacion de postura cloud..."

    cat > /usr/local/bin/evaluar-postura-cloud.sh << 'EOFPOSTURA'
#!/bin/bash
# ============================================================
# evaluar-postura-cloud.sh - Evaluacion de postura cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/cloud-posture-$(date +%Y%m%d-%H%M%S).log"

# Puntuacion por categoria
IAM_SCORE=0; IAM_MAX=0
NET_SCORE=0; NET_MAX=0
LOG_SCORE=0; LOG_MAX=0
ENC_SCORE=0; ENC_MAX=0
MON_SCORE=0; MON_MAX=0

score_check() {
    local cat="$1" result="$2" desc="$3"
    local var_score="${cat}_SCORE"
    local var_max="${cat}_MAX"
    eval "(($var_max++)) || true"
    if [[ "$result" == "PASS" ]]; then
        eval "(($var_score++)) || true"
        echo -e "  ${GREEN}[PASS]${NC} [$cat] $desc" | tee -a "$REPORT"
    elif [[ "$result" == "WARN" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} [$cat] $desc" | tee -a "$REPORT"
    else
        echo -e "  ${RED}[FAIL]${NC} [$cat] $desc" | tee -a "$REPORT"
    fi
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Evaluacion de Postura Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── IAM ──────────────────────────────────────────────────
echo -e "${BOLD}─── IAM ───${NC}" | tee -a "$REPORT"

# Check: credenciales archivos con permisos correctos
perm_ok=1
for hd in /root /home/*; do
    [[ -f "${hd}/.aws/credentials" ]] && [[ "$(stat -c '%a' "${hd}/.aws/credentials" 2>/dev/null)" != "600" ]] && perm_ok=0
    [[ -d "${hd}/.config/gcloud" ]] && [[ "$(stat -c '%a' "${hd}/.config/gcloud" 2>/dev/null)" != "700" ]] && perm_ok=0
done
[[ $perm_ok -eq 1 ]] && score_check "IAM" "PASS" "Permisos de archivos de credenciales" || score_check "IAM" "FAIL" "Permisos de archivos de credenciales inseguros"

# Check: no hay credenciales en env vars
if env | grep -q "^AWS_SECRET_ACCESS_KEY=" 2>/dev/null || env | grep -q "^GOOGLE_APPLICATION_CREDENTIALS=" 2>/dev/null; then
    score_check "IAM" "WARN" "Credenciales cloud en variables de entorno"
else
    score_check "IAM" "PASS" "Sin credenciales cloud en variables de entorno"
fi

if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    # IMDSv2
    inst="${CLOUD_INSTANCE_ID:-}"
    if [[ -n "$inst" ]]; then
        imds=$(aws ec2 describe-instances --instance-ids "$inst" \
            --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' --output text 2>/dev/null || echo "unknown")
        [[ "$imds" == "required" ]] && score_check "IAM" "PASS" "IMDSv2 enforced" || score_check "IAM" "FAIL" "IMDSv2 no enforced"
    fi

    # AdministratorAccess check
    caller=$(aws sts get-caller-identity --output json 2>/dev/null || true)
    if [[ -n "$caller" ]]; then
        arn=$(echo "$caller" | grep -o '"Arn"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || true)
        rname=$(echo "$arn" | sed 's|.*role/||; s|/.*||' || true)
        if [[ -n "$rname" ]] && [[ "$rname" != "$arn" ]]; then
            admin_check=$(aws iam list-attached-role-policies --role-name "$rname" --output text 2>/dev/null | grep -c "AdministratorAccess" || echo "0")
            [[ "$admin_check" -eq 0 ]] && score_check "IAM" "PASS" "Sin AdministratorAccess" || score_check "IAM" "FAIL" "AdministratorAccess adjunta"
        fi
    fi
fi

# ── RED ──────────────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── RED ───${NC}" | tee -a "$REPORT"

# Firewall local
if command -v iptables &>/dev/null; then
    rule_count=$(iptables -L OUTPUT -n 2>/dev/null | grep -c "169.254.169.254" || echo "0")
    [[ "$rule_count" -gt 0 ]] && score_check "NET" "PASS" "Reglas IMDS en iptables" || score_check "NET" "FAIL" "Sin reglas IMDS en iptables"
fi

# Servicios peligrosos expuestos
if command -v ss &>/dev/null; then
    dangerous=$(ss -tlnp 2>/dev/null | grep "0\.0\.0\.0:" | grep -cE ":(3306|5432|6379|27017|9200) " || echo "0")
    [[ "$dangerous" -eq 0 ]] && score_check "NET" "PASS" "Sin servicios peligrosos en 0.0.0.0" || score_check "NET" "FAIL" "$dangerous servicios peligrosos expuestos"
fi

if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    vpc="${CLOUD_VPC_ID:-}"
    if [[ -n "$vpc" ]]; then
        fl=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs | length(@)' --output text 2>/dev/null || echo "0")
        [[ "$fl" -gt 0 ]] && score_check "NET" "PASS" "VPC Flow Logs activos" || score_check "NET" "FAIL" "VPC Flow Logs no activos"
    fi
fi

# ── LOGGING ──────────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── LOGGING ───${NC}" | tee -a "$REPORT"

systemctl is-active systemd-journald &>/dev/null 2>&1 && score_check "LOG" "PASS" "journald activo" || score_check "LOG" "FAIL" "journald no activo"
systemctl is-active auditd &>/dev/null 2>&1 && score_check "LOG" "PASS" "auditd activo" || score_check "LOG" "WARN" "auditd no activo"

if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    ct=$(aws cloudtrail describe-trails --query 'trailList | length(@)' --output text 2>/dev/null || echo "0")
    [[ "$ct" -gt 0 ]] && score_check "LOG" "PASS" "CloudTrail configurado ($ct trails)" || score_check "LOG" "FAIL" "Sin CloudTrail"
fi

# ── CIFRADO ──────────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── CIFRADO ───${NC}" | tee -a "$REPORT"

if command -v lsblk &>/dev/null; then
    luks=$(lsblk -o TYPE 2>/dev/null | grep -c "crypt" || echo "0")
    [[ "$luks" -gt 0 ]] && score_check "ENC" "PASS" "Volumenes LUKS detectados" || score_check "ENC" "INFO" "Sin volumenes LUKS"
fi

if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    ebs_enc=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "unknown")
    [[ "$ebs_enc" == "True" ]] && score_check "ENC" "PASS" "EBS encryption por defecto" || score_check "ENC" "FAIL" "EBS encryption no por defecto"
fi

# ── MONITOREO ────────────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── MONITOREO ───${NC}" | tee -a "$REPORT"

# Cron de auditoria
[[ -f /etc/cron.weekly/auditoria-cloud ]] && score_check "MON" "PASS" "Auditoria cloud semanal configurada" || score_check "MON" "WARN" "Sin auditoria cloud semanal"

# Verificar cloud-provider.conf
[[ -f /etc/securizar/cloud-provider.conf ]] && score_check "MON" "PASS" "Deteccion cloud configurada" || score_check "MON" "WARN" "Sin deteccion cloud"

# ── PUNTUACION FINAL ─────────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo -e "${BOLD}  PUNTUACION POR CATEGORIA${NC}" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"

print_cat_score() {
    local cat="$1" label="$2"
    local score_var="${cat}_SCORE" max_var="${cat}_MAX"
    local score=${!score_var} max=${!max_var}
    local pct=0
    [[ $max -gt 0 ]] && pct=$((score * 100 / max))
    local color="$RED"
    [[ $pct -ge 50 ]] && color="$YELLOW"
    [[ $pct -ge 80 ]] && color="$GREEN"
    printf "  %-15s ${color}%d/%d (%d%%)${NC}\n" "$label:" "$score" "$max" "$pct" | tee -a "$REPORT"
}

print_cat_score "IAM" "IAM"
print_cat_score "NET" "Red"
print_cat_score "LOG" "Logging"
print_cat_score "ENC" "Cifrado"
print_cat_score "MON" "Monitoreo"

TOTAL_SCORE=$((IAM_SCORE + NET_SCORE + LOG_SCORE + ENC_SCORE + MON_SCORE))
TOTAL_MAX=$((IAM_MAX + NET_MAX + LOG_MAX + ENC_MAX + MON_MAX))
TOTAL_PCT=0
[[ $TOTAL_MAX -gt 0 ]] && TOTAL_PCT=$((TOTAL_SCORE * 100 / TOTAL_MAX))

echo "" | tee -a "$REPORT"
echo -e "  ${BOLD}TOTAL: $TOTAL_SCORE/$TOTAL_MAX ($TOTAL_PCT%)${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [[ $TOTAL_PCT -ge 80 ]]; then
    echo -e "  Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $TOTAL_PCT -ge 50 ]]; then
    echo -e "  Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "  Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFPOSTURA

    chmod +x /usr/local/bin/evaluar-postura-cloud.sh
    log_change "Creado" "/usr/local/bin/evaluar-postura-cloud.sh"
    log_change "Permisos" "/usr/local/bin/evaluar-postura-cloud.sh -> +x"

    # Prowler (AWS CIS benchmark tool)
    if [[ "$CLOUD_PROVIDER" == "aws" ]] && [[ $HAS_AWS_CLI -eq 1 ]]; then
        if command -v prowler &>/dev/null; then
            log_info "Prowler ya instalado: $(prowler --version 2>/dev/null || echo 'version desconocida')"
        else
            if ask "¿Instalar Prowler para auditorias CIS de AWS?"; then
                if command -v pip3 &>/dev/null; then
                    pip3 install prowler 2>/dev/null && log_change "Instalado" "prowler (AWS CIS benchmark)" || log_warn "Error instalando prowler"
                elif command -v pip &>/dev/null; then
                    pip install prowler 2>/dev/null && log_change "Instalado" "prowler (AWS CIS benchmark)" || log_warn "Error instalando prowler"
                else
                    log_warn "pip no disponible - instala prowler manualmente: pip install prowler"
                fi
            else
                log_skip "Instalacion de Prowler"
            fi
        fi
    fi

    # ScoutSuite (multi-cloud)
    if command -v scout &>/dev/null; then
        log_info "ScoutSuite ya instalado"
    else
        if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
            if ask "¿Instalar ScoutSuite para auditorias multi-cloud? (via pip)"; then
                if command -v pip3 &>/dev/null; then
                    pip3 install scoutsuite 2>/dev/null && log_change "Instalado" "scoutsuite" || log_warn "Error instalando ScoutSuite"
                else
                    pip install scoutsuite 2>/dev/null && log_change "Instalado" "scoutsuite" || log_warn "Error instalando ScoutSuite"
                fi
            else
                log_skip "Instalacion de ScoutSuite"
            fi
        fi
    fi

    log_info "Ejecuta: evaluar-postura-cloud.sh"

else
    log_skip "Evaluacion de postura de seguridad cloud"
fi

# ============================================================
# S8: PROTECCION CONTRA EXFILTRACION CLOUD
# ============================================================
log_section "S8: PROTECCION CONTRA EXFILTRACION CLOUD"

echo "Proteccion contra exfiltracion de datos cloud:"
echo "  - Verificar politicas de acceso publico en S3/Blob/GCS"
echo "  - Monitoreo de transferencia de datos salientes"
echo "  - Deteccion de exfiltracion via DNS"
echo "  - Alertas de movimiento anomalo de datos"
echo "  - Script: /usr/local/bin/detectar-exfiltracion-cloud.sh"
echo ""

if check_executable /usr/local/bin/detectar-exfiltracion-cloud.sh; then
    log_already "Deteccion de exfiltracion cloud (script ya instalado)"
elif ask "¿Crear script de deteccion de exfiltracion cloud?"; then

    log_info "Creando script de deteccion de exfiltracion cloud..."

    cat > /usr/local/bin/detectar-exfiltracion-cloud.sh << 'EOFEXFIL'
#!/bin/bash
# ============================================================
# detectar-exfiltracion-cloud.sh - Deteccion de exfiltracion
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/exfiltration-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Deteccion de Exfiltracion Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── S3/Blob/GCS acceso publico ───────────────────────────
if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    echo -e "${BOLD}─── AWS S3 Acceso Publico ───${NC}" | tee -a "$REPORT"

    # S3 Public Access Block a nivel de cuenta
    pub_block=$(aws s3control get-public-access-block \
        --account-id "$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)" \
        --output json 2>/dev/null || true)

    if [[ -n "$pub_block" ]]; then
        block_all=$(echo "$pub_block" | grep -c '"true"' 2>/dev/null || echo "0")
        if [[ "$block_all" -ge 4 ]]; then
            cr "PASS" "S3 Public Access Block completo a nivel de cuenta"
        else
            cr "WARN" "S3 Public Access Block parcial ($block_all/4 configuraciones)"
        fi
    else
        cr "FAIL" "No se pudo verificar S3 Public Access Block de cuenta"
    fi

    # Verificar buckets individuales
    echo "" | tee -a "$REPORT"
    echo -e "${BOLD}Buckets S3:${NC}" | tee -a "$REPORT"
    buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null || true)
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        # Verificar ACL publica
        acl=$(aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null || true)
        if [[ -n "$acl" ]]; then
            if echo "$acl" | grep -q "AllUsers\|AuthenticatedUsers" 2>/dev/null; then
                cr "FAIL" "Bucket '$bucket' tiene ACL publica"
            else
                cr "PASS" "Bucket '$bucket' sin ACL publica"
            fi
        fi

        # Verificar bucket policy
        policy=$(aws s3api get-bucket-policy --bucket "$bucket" --output text 2>/dev/null || true)
        if [[ -n "$policy" ]]; then
            if echo "$policy" | grep -q '"Principal"[[:space:]]*:[[:space:]]*"\*"' 2>/dev/null; then
                cr "FAIL" "Bucket '$bucket' tiene policy con Principal: *"
            else
                cr "PASS" "Bucket '$bucket' policy sin acceso publico"
            fi
        fi
    done
fi

if [[ "$CLOUD_PROVIDER" == "azure" ]] && command -v az &>/dev/null; then
    echo -e "${BOLD}─── Azure Storage Acceso Publico ───${NC}" | tee -a "$REPORT"

    storage_accounts=$(az storage account list \
        --query '[*].{name:name,publicAccess:allowBlobPublicAccess}' --output json 2>/dev/null || true)
    if [[ -n "$storage_accounts" ]] && [[ "$storage_accounts" != "[]" ]]; then
        while IFS= read -r sa_name; do
            [[ -z "$sa_name" ]] && continue
            pub_access=$(echo "$storage_accounts" | grep -A 1 "\"name\": \"$sa_name\"" | grep "publicAccess" | grep -o "true\|false\|null" | head -1 || echo "unknown")
            if [[ "$pub_access" == "true" ]]; then
                cr "FAIL" "Storage account '$sa_name' permite acceso publico a blobs"
            else
                cr "PASS" "Storage account '$sa_name' sin acceso publico"
            fi
        done < <(echo "$storage_accounts" | grep '"name"' | cut -d'"' -f4)
    fi
fi

if [[ "$CLOUD_PROVIDER" == "gcp" ]] && command -v gcloud &>/dev/null; then
    echo -e "${BOLD}─── GCS Acceso Publico ───${NC}" | tee -a "$REPORT"

    gcs_buckets=$(gcloud storage buckets list --format="value(name)" 2>/dev/null || true)
    if [[ -n "$gcs_buckets" ]]; then
        while IFS= read -r bname; do
            [[ -z "$bname" ]] && continue
            iam=$(gcloud storage buckets get-iam-policy "gs://$bname" --format=json 2>/dev/null || true)
            if [[ -n "$iam" ]] && echo "$iam" | grep -q "allUsers\|allAuthenticatedUsers" 2>/dev/null; then
                cr "FAIL" "Bucket '$bname' tiene acceso publico"
            else
                cr "PASS" "Bucket '$bname' sin acceso publico"
            fi
        done <<< "$gcs_buckets"
    fi
fi

# ── Monitoreo de trafico saliente ────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── Trafico Saliente ───${NC}" | tee -a "$REPORT"

# Verificar conexiones salientes activas
if command -v ss &>/dev/null; then
    outbound=$(ss -tnp state established 2>/dev/null | grep -cv "^State" || echo "0")
    cr "INFO" "Conexiones salientes activas: $outbound"

    # Conexiones a IPs inusuales (no RFC1918)
    external=$(ss -tn state established 2>/dev/null | awk '{print $5}' | \
        grep -v "^127\.\|^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[01]\.\|^192\.168\.\|^::1\|^fe80:" | \
        sort -u | wc -l || echo "0")
    cr "INFO" "Destinos externos unicos: $external"
fi

# Verificar DNS
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── DNS Exfiltracion ───${NC}" | tee -a "$REPORT"

# Verificar consultas DNS grandes (posible tunneling)
if [[ -f /var/log/syslog ]]; then
    dns_long=$(grep -c "query.*TXT\|query.*type65" /var/log/syslog 2>/dev/null || echo "0")
    if [[ "$dns_long" -gt 100 ]]; then
        cr "WARN" "Alto volumen de consultas DNS TXT: $dns_long (posible tunneling)"
    else
        cr "PASS" "Volumen normal de consultas DNS TXT: $dns_long"
    fi
elif command -v journalctl &>/dev/null; then
    dns_long=$(journalctl -u systemd-resolved --since "1 hour ago" 2>/dev/null | grep -c "TXT\|type65" || echo "0")
    if [[ "$dns_long" -gt 100 ]]; then
        cr "WARN" "Alto volumen de consultas DNS TXT (ultima hora): $dns_long"
    else
        cr "PASS" "Volumen normal de consultas DNS TXT: $dns_long"
    fi
fi

# Verificar transferencias grandes recientes
echo "" | tee -a "$REPORT"
echo -e "${BOLD}─── Transferencias de datos ───${NC}" | tee -a "$REPORT"
if command -v ss &>/dev/null; then
    # Conexiones con alto trafico
    high_traffic=$(ss -tnpi 2>/dev/null | grep -c "bytes_sent:[0-9]\{9,\}" || echo "0")
    if [[ "$high_traffic" -gt 0 ]]; then
        cr "WARN" "$high_traffic conexiones con >1GB enviados"
    else
        cr "PASS" "Sin conexiones con transferencias masivas"
    fi
fi

echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 2 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFEXFIL

    chmod +x /usr/local/bin/detectar-exfiltracion-cloud.sh
    log_change "Creado" "/usr/local/bin/detectar-exfiltracion-cloud.sh"
    log_change "Permisos" "/usr/local/bin/detectar-exfiltracion-cloud.sh -> +x"

    # Verificacion rapida de acceso publico
    if [[ "$CLOUD_PROVIDER" == "aws" ]] && [[ $HAS_AWS_CLI -eq 1 ]]; then
        log_info "Verificando S3 Public Access Block..."
        pub_block=$(aws s3control get-public-access-block \
            --account-id "$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)" 2>/dev/null || true)
        if [[ -n "$pub_block" ]]; then
            block_count=$(echo "$pub_block" | grep -c '"true"' 2>/dev/null || echo "0")
            if [[ "$block_count" -ge 4 ]]; then
                log_info "S3 Public Access Block: completo (4/4)"
            else
                log_warn "S3 Public Access Block: parcial ($block_count/4)"
            fi
        fi
    fi

    log_info "Ejecuta: detectar-exfiltracion-cloud.sh"


    # ── S8b: Filtrado de egress cloud ──
    if ask "¿Configurar filtrado de egress cloud?"; then
        mkdir -p /etc/securizar
        cat > /etc/securizar/cloud-egress-whitelist.conf << 'EOFWHITELIST'
# Whitelist de destinos de egress permitidos
# Formato: IP/CIDR o dominio por línea
# Generado por seguridad-cloud.sh

# AWS endpoints (ajustar región)
# 52.94.0.0/16
# 54.239.0.0/16

# Azure endpoints
# 13.64.0.0/11

# GCP endpoints
# 35.190.0.0/16

# Servicios esenciales
# updates.example.com
# api.example.com
EOFWHITELIST

        log_change "Creado" "/etc/securizar/cloud-egress-whitelist.conf"

        cat > /usr/local/bin/filtrado-egress-cloud.sh << 'EOFEGRESS'
#!/bin/bash
# Filtrado de egress cloud - limitar tráfico saliente
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

WHITELIST="/etc/securizar/cloud-egress-whitelist.conf"

echo -e "${BOLD}=== FILTRADO DE EGRESS CLOUD ===${NC}"

case "${1:-status}" in
    status)
        echo -e "\n${BOLD}Conexiones salientes actuales:${NC}"
        ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
        echo -e "\n${BOLD}Whitelist configurada:${NC}"
        if [[ -f "$WHITELIST" ]]; then
            grep -v "^#" "$WHITELIST" | grep -v "^$" | while read -r entry; do
                echo "  $entry"
            done
        else
            echo "  No configurada"
        fi
        ;;
    check)
        echo -e "\n${BOLD}Verificando conexiones vs whitelist...${NC}"
        VIOLATIONS=0
        while read -r dest; do
            [[ -z "$dest" ]] && continue
            ALLOWED=false
            while IFS= read -r entry; do
                [[ -z "$entry" ]] && continue
                [[ "$entry" == "#"* ]] && continue
                if [[ "$dest" == "$entry"* ]]; then
                    ALLOWED=true
                    break
                fi
            done < "$WHITELIST"
            if [[ "$ALLOWED" == "false" ]]; then
                PROC=$(ss -tnp | grep "$dest" | grep -oP 'users:\(\("\K[^"]+' | head -1 || echo "?")
                echo -e "  ${YELLOW}!!${NC} Destino no whitelisted: $dest ($PROC)"
                ((VIOLATIONS++))
            fi
        done < <(ss -tn state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u)
        echo -e "\n${BOLD}Violaciones: $VIOLATIONS${NC}"
        ;;
    *)
        echo "Uso: $0 {status|check}"
        ;;
esac
EOFEGRESS

        chmod 755 /usr/local/bin/filtrado-egress-cloud.sh
        log_change "Creado" "/usr/local/bin/filtrado-egress-cloud.sh"
        log_info "Filtrado de egress cloud configurado"
    else
        log_skip "Filtrado de egress cloud"
    fi

else
    log_skip "Proteccion contra exfiltracion cloud"
fi

# ============================================================
# S9: HARDENING DE CONTENEDORES EN CLOUD
# ============================================================
log_section "S9: HARDENING DE CONTENEDORES EN CLOUD"

echo "Hardening de contenedores en entornos cloud:"
echo "  - Verificar ECS/EKS/AKS/GKE presente"
echo "  - Seguridad de runtime de contenedores"
echo "  - Pod security policies / security contexts"
echo "  - ECR/ACR/GCR image scanning"
echo "  - Contenedores privilegiados"
echo "  - Script: /usr/local/bin/auditar-contenedores-cloud.sh"
echo ""

if check_executable /usr/local/bin/auditar-contenedores-cloud.sh; then
    log_already "Auditoria de contenedores cloud (script ya instalado)"
elif ask "¿Crear script de auditoria de contenedores cloud?"; then

    log_info "Creando script de auditoria de contenedores cloud..."

    # Detectar orquestadores
    HAS_DOCKER=0; HAS_KUBECTL=0; HAS_PODMAN=0
    command -v docker &>/dev/null && HAS_DOCKER=1
    command -v kubectl &>/dev/null && HAS_KUBECTL=1
    command -v podman &>/dev/null && HAS_PODMAN=1

    [[ $HAS_DOCKER -eq 1 ]] && log_info "Docker detectado"
    [[ $HAS_KUBECTL -eq 1 ]] && log_info "kubectl detectado"
    [[ $HAS_PODMAN -eq 1 ]] && log_info "Podman detectado"

    cat > /usr/local/bin/auditar-contenedores-cloud.sh << 'EOFCONTAINER'
#!/bin/bash
# ============================================================
# auditar-contenedores-cloud.sh - Auditoria de contenedores cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO=0
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/container-cloud-$(date +%Y%m%d-%H%M%S).log"

cr() {
    local s="$1" d="$2"
    case "$s" in
        PASS) echo -e "  ${GREEN}[PASS]${NC} $d" | tee -a "$REPORT"; ((PASS++)) || true ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC} $d" | tee -a "$REPORT"; ((FAIL++)) || true ;;
        WARN) echo -e "  ${YELLOW}[WARN]${NC} $d" | tee -a "$REPORT"; ((WARN++)) || true ;;
        INFO) echo -e "  ${DIM}[INFO]${NC} $d" | tee -a "$REPORT"; ((INFO++)) || true ;;
    esac
}

echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee "$REPORT"
echo -e "${CYAN}  Auditoria Contenedores Cloud - $(date)${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# ── Deteccion de orquestadores ───────────────────────────
echo -e "${BOLD}─── Entorno de contenedores ───${NC}" | tee -a "$REPORT"

command -v docker &>/dev/null && cr "INFO" "Docker presente" || cr "INFO" "Docker no detectado"
command -v podman &>/dev/null && cr "INFO" "Podman presente" || cr "INFO" "Podman no detectado"
command -v kubectl &>/dev/null && cr "INFO" "kubectl presente" || cr "INFO" "kubectl no detectado"
command -v ctr &>/dev/null && cr "INFO" "containerd (ctr) presente"
command -v crictl &>/dev/null && cr "INFO" "CRI tools (crictl) presente"

# Verificar si estamos en ECS/EKS/AKS/GKE
if [[ -f /etc/ecs/ecs.config ]] || curl -sf -m 2 "http://169.254.170.2/v2/metadata" &>/dev/null; then
    cr "INFO" "Entorno AWS ECS detectado"
fi
if [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    cr "INFO" "Ejecutando dentro de un pod Kubernetes"
fi
echo "" | tee -a "$REPORT"

# ── Contenedores privilegiados ───────────────────────────
echo -e "${BOLD}─── Contenedores privilegiados ───${NC}" | tee -a "$REPORT"

if command -v docker &>/dev/null; then
    priv_containers=$(docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r cid cname; do
        is_priv=$(docker inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
        [[ "$is_priv" == "true" ]] && echo "$cname"
    done || true)
    if [[ -n "$priv_containers" ]]; then
        while IFS= read -r pname; do
            cr "FAIL" "Contenedor privilegiado: $pname"
        done <<< "$priv_containers"
    else
        cr "PASS" "Sin contenedores privilegiados (Docker)"
    fi

    # Verificar root containers
    root_containers=$(docker ps -q 2>/dev/null | while read -r cid; do
        user=$(docker inspect "$cid" --format '{{.Config.User}}' 2>/dev/null || echo "")
        name=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null || echo "$cid")
        [[ -z "$user" || "$user" == "root" || "$user" == "0" ]] && echo "$name"
    done || true)
    if [[ -n "$root_containers" ]]; then
        root_n=$(echo "$root_containers" | wc -l)
        cr "WARN" "$root_n contenedores ejecutando como root"
    else
        cr "PASS" "Sin contenedores ejecutando como root"
    fi
fi

if command -v podman &>/dev/null; then
    podman_priv=$(podman ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r cid cname; do
        is_priv=$(podman inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo "false")
        [[ "$is_priv" == "true" ]] && echo "$cname"
    done || true)
    if [[ -n "$podman_priv" ]]; then
        cr "FAIL" "Contenedores privilegiados en Podman detectados"
    else
        cr "PASS" "Sin contenedores privilegiados (Podman)"
    fi
fi
echo "" | tee -a "$REPORT"

# ── Kubernetes security ──────────────────────────────────
if command -v kubectl &>/dev/null; then
    echo -e "${BOLD}─── Kubernetes Security ───${NC}" | tee -a "$REPORT"

    # Verificar contexto
    k_ctx=$(kubectl config current-context 2>/dev/null || echo "none")
    cr "INFO" "Contexto K8s: $k_ctx"

    if [[ "$k_ctx" != "none" ]]; then
        # Pod Security Standards
        pss=$(kubectl get ns --show-labels 2>/dev/null | grep -c "pod-security" || echo "0")
        if [[ "$pss" -gt 0 ]]; then
            cr "PASS" "$pss namespaces con Pod Security Standards"
        else
            cr "WARN" "Sin Pod Security Standards configurados"
        fi

        # Pods privilegiados
        priv_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
            grep -c '"privileged": true' 2>/dev/null || echo "0")
        if [[ "$priv_pods" -eq 0 ]]; then
            cr "PASS" "Sin pods privilegiados"
        else
            cr "FAIL" "$priv_pods pods privilegiados detectados"
        fi

        # Pods con hostNetwork
        hostnet=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
            grep -c '"hostNetwork": true' 2>/dev/null || echo "0")
        if [[ "$hostnet" -eq 0 ]]; then
            cr "PASS" "Sin pods con hostNetwork"
        else
            cr "WARN" "$hostnet pods con hostNetwork"
        fi

        # Network Policies
        netpol=$(kubectl get networkpolicies --all-namespaces 2>/dev/null | grep -cv "^NAMESPACE" || echo "0")
        if [[ "$netpol" -gt 0 ]]; then
            cr "PASS" "$netpol Network Policies configuradas"
        else
            cr "WARN" "Sin Network Policies"
        fi

        # RBAC check
        cluster_admins=$(kubectl get clusterrolebindings -o json 2>/dev/null | \
            grep -c '"cluster-admin"' 2>/dev/null || echo "0")
        cr "INFO" "Bindings cluster-admin: $cluster_admins"
    fi
    echo "" | tee -a "$REPORT"
fi

# ── Image scanning ───────────────────────────────────────
echo -e "${BOLD}─── Image Scanning ───${NC}" | tee -a "$REPORT"

if [[ "$CLOUD_PROVIDER" == "aws" ]] && command -v aws &>/dev/null; then
    # ECR scan config
    ecr_scan=$(aws ecr describe-registry --query 'scanningConfiguration.scanType' --output text 2>/dev/null || echo "unknown")
    if [[ "$ecr_scan" == "ENHANCED" ]]; then
        cr "PASS" "ECR Enhanced Scanning habilitado"
    elif [[ "$ecr_scan" == "BASIC" ]]; then
        cr "WARN" "ECR Basic Scanning (considerar Enhanced)"
    else
        cr "INFO" "ECR scan config: $ecr_scan"
    fi
fi

if [[ "$CLOUD_PROVIDER" == "gcp" ]] && command -v gcloud &>/dev/null; then
    # Artifact Registry / Container Analysis
    vuln_scanning=$(gcloud services list --enabled --format="value(name)" 2>/dev/null | grep -c "containeranalysis" || echo "0")
    if [[ "$vuln_scanning" -gt 0 ]]; then
        cr "PASS" "Container Analysis API habilitada (vulnerability scanning)"
    else
        cr "WARN" "Container Analysis API no habilitada"
    fi
fi

# Trivy check
if command -v trivy &>/dev/null; then
    cr "PASS" "Trivy scanner disponible"
else
    cr "INFO" "Trivy no instalado (recomendado para escaneo de imagenes)"
fi

echo "" | tee -a "$REPORT"
echo -e "${BOLD}════════════════════════════════════════════${NC}" | tee -a "$REPORT"
TOTAL=$((PASS + FAIL + WARN))
echo -e "Resultado: ${GREEN}$PASS PASS${NC} | ${YELLOW}$WARN WARN${NC} | ${RED}$FAIL FAIL${NC} | ${DIM}$INFO INFO${NC}" | tee -a "$REPORT"
if [[ $FAIL -eq 0 ]]; then echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $FAIL -le 2 ]]; then echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi
echo "" | tee -a "$REPORT"
echo "Reporte: $REPORT"
EOFCONTAINER

    chmod +x /usr/local/bin/auditar-contenedores-cloud.sh
    log_change "Creado" "/usr/local/bin/auditar-contenedores-cloud.sh"
    log_change "Permisos" "/usr/local/bin/auditar-contenedores-cloud.sh -> +x"

    # Verificacion rapida
    if command -v docker &>/dev/null; then
        running=$(docker ps -q 2>/dev/null | wc -l || echo "0")
        log_info "Docker: $running contenedores en ejecucion"
        priv=$(docker ps --format '{{.ID}}' 2>/dev/null | while read -r cid; do
            docker inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null
        done | grep -c "true" || echo "0")
        if [[ "$priv" -gt 0 ]]; then
            log_warn "$priv contenedores privilegiados detectados"
        else
            log_info "Sin contenedores privilegiados"
        fi
    fi

    if command -v kubectl &>/dev/null; then
        k_ctx=$(kubectl config current-context 2>/dev/null || echo "none")
        log_info "Kubernetes contexto: $k_ctx"
    fi

    log_info "Ejecuta: auditar-contenedores-cloud.sh"

else
    log_skip "Hardening de contenedores en cloud"
fi

# ============================================================
# S10: AUDITORIA INTEGRAL DE SEGURIDAD CLOUD
# ============================================================
log_section "S10: AUDITORIA INTEGRAL DE SEGURIDAD CLOUD"

echo "Auditoria integral que ejecuta todos los checks anteriores:"
echo "  - Ejecuta verificaciones de S1 a S9"
echo "  - Genera puntuacion comprehensiva"
echo "  - Compara contra CIS Cloud Benchmarks"
echo "  - Reporte en /var/log/securizar/auditoria-cloud-FECHA.log"
echo "  - Cron semanal: /etc/cron.weekly/auditoria-cloud"
echo "  - Script: /usr/local/bin/auditoria-seguridad-cloud.sh"
echo ""

if check_executable /usr/local/bin/auditoria-seguridad-cloud.sh; then
    log_already "Auditoria integral de seguridad cloud (script ya instalado)"
elif ask "¿Crear script de auditoria integral de seguridad cloud?"; then

    log_info "Creando script de auditoria integral de seguridad cloud..."

    cat > /usr/local/bin/auditoria-seguridad-cloud.sh << 'EOFAUDIT'
#!/bin/bash
# ============================================================
# auditoria-seguridad-cloud.sh - Auditoria integral cloud
# Generado por seguridad-cloud.sh - Modulo 52 Securizar Suite
# Ejecuta todos los scripts de auditoria cloud y genera
# reporte consolidado.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
REPORT_DIR="/var/log/securizar"; mkdir -p "$REPORT_DIR"
FECHA=$(date +%Y%m%d-%H%M%S)
REPORT="$REPORT_DIR/auditoria-cloud-${FECHA}.log"
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_WARN=0

echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}" | tee "$REPORT"
echo -e "${CYAN}${BOLD}║   AUDITORIA INTEGRAL DE SEGURIDAD CLOUD                    ║${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}║   Modulo 52 - Securizar Suite                              ║${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}║   $(date)                              ║${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}║   Hostname: $(hostname)$(printf '%*s' $((37 - ${#HOSTNAME})) '')║${NC}" | tee -a "$REPORT"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Cargar configuracion
CLOUD_PROVIDER="unknown"
[[ -f /etc/securizar/cloud-provider.conf ]] && source /etc/securizar/cloud-provider.conf
echo -e "Proveedor cloud: ${BOLD}${CLOUD_PROVIDER}${NC}" | tee -a "$REPORT"
echo -e "Instance ID: ${CLOUD_INSTANCE_ID:-N/A}" | tee -a "$REPORT"
echo -e "Region: ${CLOUD_REGION:-N/A}" | tee -a "$REPORT"
echo -e "Tipo: ${CLOUD_INSTANCE_TYPE:-N/A}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Funcion para ejecutar sub-scripts y capturar resultado
run_audit() {
    local script="$1"
    local label="$2"
    echo -e "${BOLD}── $label ──${NC}" | tee -a "$REPORT"

    if [[ -x "$script" ]]; then
        local output
        output=$("$script" 2>&1 || true)
        echo "$output" >> "$REPORT"

        # Extraer contadores del output
        local p f w
        p=$(echo "$output" | grep -o '\[PASS\]' | wc -l || echo "0")
        f=$(echo "$output" | grep -o '\[FAIL\]' | wc -l || echo "0")
        w=$(echo "$output" | grep -o '\[WARN\]' | wc -l || echo "0")
        ((TOTAL_PASS += p)) || true
        ((TOTAL_FAIL += f)) || true
        ((TOTAL_WARN += w)) || true

        echo -e "  ${GREEN}$p PASS${NC} | ${YELLOW}$w WARN${NC} | ${RED}$f FAIL${NC}" | tee -a "$REPORT"
    else
        echo -e "  ${DIM}Script no disponible: $script${NC}" | tee -a "$REPORT"
    fi
    echo "" | tee -a "$REPORT"
}

# Ejecutar todas las auditorias
run_audit "/usr/local/bin/verificar-imds.sh" "1. IMDS Security"
run_audit "/usr/local/bin/auditar-cloud-iam.sh" "2. IAM Permissions"
run_audit "/usr/local/bin/auditar-security-groups.sh" "3. Network Security"
run_audit "/usr/local/bin/auditar-cifrado-cloud.sh" "4. Encryption"
run_audit "/usr/local/bin/verificar-cloud-logging.sh" "5. Logging & Monitoring"
run_audit "/usr/local/bin/evaluar-postura-cloud.sh" "6. Security Posture"
run_audit "/usr/local/bin/detectar-exfiltracion-cloud.sh" "7. Data Exfiltration"
run_audit "/usr/local/bin/auditar-contenedores-cloud.sh" "8. Container Security"

# ── Resumen consolidado ──────────────────────────────────
echo "" | tee -a "$REPORT"
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}" | tee -a "$REPORT"
echo -e "${BOLD}║   RESUMEN CONSOLIDADO                                      ║${NC}" | tee -a "$REPORT"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN))
echo -e "Total checks: $TOTAL" | tee -a "$REPORT"
echo -e "  ${GREEN}PASS: $TOTAL_PASS${NC}" | tee -a "$REPORT"
echo -e "  ${YELLOW}WARN: $TOTAL_WARN${NC}" | tee -a "$REPORT"
echo -e "  ${RED}FAIL: $TOTAL_FAIL${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$((TOTAL_PASS * 100 / TOTAL))

echo -e "Puntuacion: ${BOLD}$SCORE%${NC}" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [[ $SCORE -ge 80 ]] && [[ $TOTAL_FAIL -eq 0 ]]; then
    echo -e "Estado: ${GREEN}${BOLD}SEGURO${NC}" | tee -a "$REPORT"
elif [[ $SCORE -ge 50 ]]; then
    echo -e "Estado: ${YELLOW}${BOLD}MEJORABLE${NC}" | tee -a "$REPORT"
else
    echo -e "Estado: ${RED}${BOLD}INSEGURO${NC}" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo "Reporte completo: $REPORT" | tee -a "$REPORT"

# Symlink a latest
ln -sf "$REPORT" "$REPORT_DIR/auditoria-cloud-latest.log"

# Generar resumen JSON
JSON_FILE="$REPORT_DIR/auditoria-cloud-${FECHA}.json"
cat > "$JSON_FILE" << EOFJSON
{
    "timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "cloud_provider": "${CLOUD_PROVIDER}",
    "instance_id": "${CLOUD_INSTANCE_ID:-}",
    "region": "${CLOUD_REGION:-}",
    "total_checks": $TOTAL,
    "pass": $TOTAL_PASS,
    "warn": $TOTAL_WARN,
    "fail": $TOTAL_FAIL,
    "score_percent": $SCORE,
    "report_file": "$REPORT"
}
EOFJSON
chmod 600 "$JSON_FILE"
echo "Resumen JSON: $JSON_FILE"
ln -sf "$JSON_FILE" "$REPORT_DIR/auditoria-cloud-latest.json"
EOFAUDIT

    chmod +x /usr/local/bin/auditoria-seguridad-cloud.sh
    log_change "Creado" "/usr/local/bin/auditoria-seguridad-cloud.sh"
    log_change "Permisos" "/usr/local/bin/auditoria-seguridad-cloud.sh -> +x"

    # --- Cron semanal ---
    log_info "Configurando auditoria semanal..."

    cat > /etc/cron.weekly/auditoria-cloud << 'EOFCRON'
#!/bin/bash
# Auditoria semanal de seguridad cloud - securizar Modulo 52
/usr/local/bin/auditoria-seguridad-cloud.sh > /var/log/securizar/auditoria-cloud-cron.log 2>&1

# Alertar si estado es INSEGURO
if grep -q "INSEGURO" /var/log/securizar/auditoria-cloud-cron.log 2>/dev/null; then
    logger -t auditoria-cloud "ALERTA: Estado de seguridad cloud INSEGURO"
fi
EOFCRON

    chmod 700 /etc/cron.weekly/auditoria-cloud
    log_change "Creado" "/etc/cron.weekly/auditoria-cloud"
    log_change "Permisos" "/etc/cron.weekly/auditoria-cloud -> 700"
    log_info "Auditoria semanal programada en cron.weekly"

    log_info "Ejecuta: auditoria-seguridad-cloud.sh"

else
    log_skip "Auditoria integral de seguridad cloud"
fi

# ============================================================
# RESUMEN FINAL
# ============================================================
show_changes_summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       SEGURIDAD CLOUD - MODULO 52 COMPLETADO              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
log_info "Backups guardados en: $BACKUP_DIR"
echo ""

echo "Scripts instalados:"
for script in \
    /usr/local/bin/verificar-imds.sh \
    /usr/local/bin/auditar-cloud-iam.sh \
    /usr/local/bin/auditar-security-groups.sh \
    /usr/local/bin/auditar-cifrado-cloud.sh \
    /usr/local/bin/verificar-cloud-logging.sh \
    /usr/local/bin/evaluar-postura-cloud.sh \
    /usr/local/bin/detectar-exfiltracion-cloud.sh \
    /usr/local/bin/auditar-contenedores-cloud.sh \
    /usr/local/bin/auditoria-seguridad-cloud.sh; do
    if [[ -x "$script" ]]; then
        echo -e "  ${GREEN}[OK]${NC} $(basename "$script")"
    else
        echo -e "  ${YELLOW}[--]${NC} $(basename "$script") no instalado"
    fi
done
echo ""

echo "Comandos utiles:"
echo "  - Verificar IMDS:          verificar-imds.sh"
echo "  - Auditar IAM:             auditar-cloud-iam.sh"
echo "  - Security Groups:         auditar-security-groups.sh"
echo "  - Cifrado:                 auditar-cifrado-cloud.sh"
echo "  - Logging:                 verificar-cloud-logging.sh"
echo "  - Postura cloud:           evaluar-postura-cloud.sh"
echo "  - Exfiltracion:            detectar-exfiltracion-cloud.sh"
echo "  - Contenedores:            auditar-contenedores-cloud.sh"
echo "  - Auditoria integral:      auditoria-seguridad-cloud.sh"
echo ""
log_warn "RECOMENDACION: Ejecuta 'auditoria-seguridad-cloud.sh' para una evaluacion completa"
log_info "Modulo 52 completado"
echo ""
