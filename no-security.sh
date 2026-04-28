#!/usr/bin/env bash
# Toggle OpenShift's two pod-admission gatekeepers (SCC + Pod Security Admission)
# so user namespaces behave like vanilla Kubernetes.
#
# Usage: ./no-security.sh <command>
#
#   off              SCC+PSA off on existing user namespaces
#   on               restore SCC+PSA
#   status           current SCC+PSA state
#   template-off     install a project-request template so NEW namespaces are born PSA privileged
#   template-on      remove the template (new namespaces use default PSA restricted again)
#   template-status  template wiring state
#
# Fully reversible. No data is deleted.

set -euo pipefail

user_namespaces() {
  oc get ns -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' \
    | grep -Ev '^(kube-|openshift-|openshift$|default$|assisted-installer$)'
}

scc_off() {
  oc adm policy add-scc-to-group privileged system:authenticated
  oc adm policy add-scc-to-group privileged system:serviceaccounts
}

scc_on() {
  oc adm policy remove-scc-from-group privileged system:authenticated
  oc adm policy remove-scc-from-group privileged system:serviceaccounts
}

psa_off() {
  for ns in $(user_namespaces); do
    oc label ns "$ns" --overwrite \
      pod-security.kubernetes.io/enforce=privileged \
      pod-security.kubernetes.io/warn=privileged \
      pod-security.kubernetes.io/audit=privileged
  done
}

psa_on() {
  for ns in $(user_namespaces); do
    oc label ns "$ns" \
      pod-security.kubernetes.io/enforce- \
      pod-security.kubernetes.io/warn- \
      pod-security.kubernetes.io/audit- 2>/dev/null || true
  done
}

status() {
  echo "== SCC privileged: legacy .groups field =="
  oc get scc privileged -o jsonpath='{.groups}'; echo
  echo "== SCC privileged: RBAC ClusterRoleBindings =="
  oc get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="system:openshift:scc:privileged")]}  {.metadata.name}: {range .subjects[*]}{.kind}/{.name} {end}{"\n"}{end}'
  echo "== user namespaces with PSA enforce=privileged =="
  for ns in $(user_namespaces); do
    label=$(oc get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
    printf "  %-30s %s\n" "$ns" "${label:-<none>}"
  done
}

template_off() {
  oc apply -n openshift-config -f - <<'EOF'
apiVersion: template.openshift.io/v1
kind: Template
metadata:
  name: project-request
objects:
- apiVersion: project.openshift.io/v1
  kind: Project
  metadata:
    name: ${PROJECT_NAME}
    annotations:
      openshift.io/description: ${PROJECT_DESCRIPTION}
      openshift.io/display-name: ${PROJECT_DISPLAYNAME}
      openshift.io/requester: ${PROJECT_REQUESTING_USER}
    labels:
      pod-security.kubernetes.io/enforce: privileged
      pod-security.kubernetes.io/warn:    privileged
      pod-security.kubernetes.io/audit:   privileged
- apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: admin
    namespace: ${PROJECT_NAME}
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: admin
  subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: ${PROJECT_ADMIN_USER}
parameters:
- name: PROJECT_NAME
- name: PROJECT_DISPLAYNAME
- name: PROJECT_DESCRIPTION
- name: PROJECT_ADMIN_USER
- name: PROJECT_REQUESTING_USER
EOF
  oc patch project.config.openshift.io/cluster --type=merge \
    -p '{"spec":{"projectRequestTemplate":{"name":"project-request"}}}'
}

template_on() {
  oc patch project.config.openshift.io/cluster --type=merge \
    -p '{"spec":{"projectRequestTemplate":null}}'
  oc delete template project-request -n openshift-config --ignore-not-found
}

template_status() {
  echo "== projectRequestTemplate wiring (project.config/cluster) =="
  oc get project.config.openshift.io/cluster -o jsonpath='{.spec.projectRequestTemplate}'; echo
  echo "== template object in openshift-config =="
  oc get template project-request -n openshift-config -o jsonpath='{.metadata.name}{"\n"}' 2>/dev/null || echo "  <not present>"
}

cmd="${1:-}"
[[ "$cmd" =~ ^(off|on|status|template-off|template-on|template-status)$ ]] || { sed -n '2,14p' "$0"; exit 1; }

echo "cluster: $(oc whoami --show-server)   user: $(oc whoami)"

if [[ "$cmd" == "off" || "$cmd" == "template-off" ]]; then
  read -r -p "really disable cluster security on this cluster? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "aborted"; exit 1; }
fi

case "$cmd" in
  off)             scc_off; psa_off;       echo "⚠️  running WITHOUT bulletproof OpenShift security" ;;
  on)              scc_on;  psa_on;        echo "🛡️  bulletproof OpenShift security restored" ;;
  status)          status ;;
  template-off)    template_off;           echo "⚠️  new namespaces will be born PSA privileged" ;;
  template-on)     template_on;            echo "🛡️  new namespaces use default PSA restricted again" ;;
  template-status) template_status ;;
esac

echo "✅ done: $cmd"
