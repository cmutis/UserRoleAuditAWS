# IAM Access Governance – Permission Diff (AWS)

## Objetivo
Identificar permisos IAM **realmente necesarios** comparando:
- Acciones permitidas por políticas adjuntas
- Acciones realmente ejecutadas (CloudTrail)

Esto permite crear **políticas y roles personalizados de mínimo privilegio**.

---

## Modelo
1. Extraer acciones permitidas (IAM policies)
2. Extraer acciones usadas (CloudTrail)
3. Comparar
4. Identificar permisos no usados
5. Recomendar remoción

---

## Fuente de verdad
- IAM → permisos teóricos
- CloudTrail → uso real

No se infiere ni se inventa información.

---

## Salida
Archivo Excel:

IAM_Access_Review_<YEAR>-Q<QUARTER>.xlsx


Hoja:
- Permission_Diff

Columnas:
- Group
- Action
- Allowed
- Used
- Effective
- Recommendation

---

## Uso recomendado
- Ventana de análisis: 90–180 días
- Validación con equipos técnicos
- Remoción progresiva
- Mantener excepciones documentadas

---

## Frase de defensa auditoría
“Least privilege is enforced by comparing IAM allowed actions with actual actions observed in CloudTrail over a defined review period.”

---

## Ejecución
```bash
chmod +x iam_access_governance.sh
./iam_access_governance.sh
```

---

## Configuración opcional
Puedes crear un archivo `config.env` en la raíz del proyecto para centralizar parámetros:

```bash
PROFILE=AWSProdCyberArchitect
LOOKBACK_DAYS=180
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
CLOUDTRAIL_MAX_RESULTS=50
# Lista separada por comas (si se omite, se intenta autodescubrir)
CLOUDTRAIL_REGIONS=us-east-1,us-west-2
SIMULATE_EFFECTIVE=true
SIMULATE_ONLY_USED=true
```

Nota:
- El análisis detallado usa CloudTrail y políticas IAM para `Permission_Diff`.

Salida adicional:
- `IAM_Access_Review_<YEAR>-Q<QUARTER>.json` (útil para integraciones).
