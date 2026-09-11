{{- define "syouyu.databaseTlsEnv" -}}
{{- if .Values.databaseTls.caSecretName }}
{{- range .Values.extraEnv }}
{{- if eq .name "PGSSLROOTCERT" }}
{{- fail "extraEnv must not override PGSSLROOTCERT when databaseTls.caSecretName is set" }}
{{- end }}
{{- end }}
- name: PGSSLROOTCERT
  valueFrom:
    secretKeyRef:
      name: {{ .Values.databaseTls.caSecretName | quote }}
      key: {{ required "databaseTls.caSecretKey is required" .Values.databaseTls.caSecretKey | quote }}
      optional: false
{{- end }}
{{- end }}
