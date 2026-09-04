{{- define "syouyu.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "syouyu.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "syouyu.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "syouyu.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: heterocloud-syouyu
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "syouyu.selectorLabels" -}}
app.kubernetes.io/name: {{ include "syouyu.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "syouyu.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "syouyu.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "syouyu.garageServiceAccountName" -}}
{{- if .Values.garage.serviceAccount.create }}
{{- default (printf "%s-garage" (include "syouyu.fullname" .)) .Values.garage.serviceAccount.name }}
{{- else }}
{{- required "garage.serviceAccount.name is required when garage.serviceAccount.create=false" .Values.garage.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "syouyu.secretName" -}}
{{- if .Values.secrets.create }}
{{- printf "%s-secrets" (include "syouyu.fullname" .) }}
{{- else }}
{{- required "secrets.existingSecret is required when secrets.create=false" .Values.secrets.existingSecret }}
{{- end }}
{{- end }}

{{- define "syouyu.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{- define "syouyu.garageName" -}}
{{- printf "%s-garage" (include "syouyu.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "syouyu.garageConfigName" -}}
{{- default (printf "%s-config" (include "syouyu.garageName" .)) .Values.garage.existingConfigMap }}
{{- end }}

{{- define "syouyu.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "syouyu.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}
