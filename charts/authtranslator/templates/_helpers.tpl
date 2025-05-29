{{- define "authtranslator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authtranslator.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- $fullname := printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- if .Values.fullnameOverride }}
{{- $fullname = .Values.fullnameOverride -}}
{{- end -}}
{{- $fullname -}}
{{- end -}}

{{- define "authtranslator.labels" -}}
helm.sh/chart: {{ include "authtranslator.chart" . }}
app.kubernetes.io/name: {{ include "authtranslator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "authtranslator.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
