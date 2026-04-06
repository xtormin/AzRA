# AzRA - Azure Reconnaissance & Analysis

<p align="center">
  <img src="Images/azra_banner.jpeg" alt="AzRA Banner" width="100%">
</p>

Kit de herramientas PowerShell para reconocimiento y pruebas de seguridad en Azure y Microsoft 365.

## 📑 Índice

1. [🚀 Inicio Rápido](#-inicio-rápido)
   - [Importar](#importar)
   - [Ejemplos de Uso Básico](#ejemplos-de-uso-básico)
2. [🔐 Autenticación](#-autenticación)
   - [Configuración de Tokens](#configuración-de-tokens)
3. [📚 Reconocimiento Interno (Azure/M365)](#-reconocimiento-interno-azurem365)
   - [Funciones Disponibles](#funciones-disponibles)
   - [Ejemplos por Función](#ejemplos-por-función)
   - [Ejemplo de Flujo de Enumeración](#ejemplo-de-flujo-de-enumeración-completo)
4. [🌐 Reconocimiento Externo (O365)](#-reconocimiento-externo-o365)
   - [Funciones Disponibles](#funciones-disponibles-1)
   - [Ejemplos de Uso](#ejemplos-de-uso)
5. [📝 Licencia](#-licencia)

## 🚀 Inicio Rápido

### Importar

**Importar el módulo:**
```powershell
Import-Module .\AzRA.psd1
```

**Obtener comandos disponibles:**
```powershell
Get-Command -Module AzRA
```

**Usar ayuda para cualquier función:**
```powershell
Get-Help Get-AzRA-Subscriptions -Full
```

### Ejemplos de Uso Básico

**Listar todas las suscripciones de Azure:**
```powershell
$token = "eyJ0eXAiOiJKV1QiLCJhbGc..."  # Tu token de Azure Management
Get-AzRA-Subscriptions -AccessToken $token
```

**Listar todos los usuarios:**
```powershell
$graphToken = "eyJ0eXAiOiJKV1QiLCJhbGc..."  # Tu token de Microsoft Graph
Get-AzRA-Users -AccessToken $graphToken
```

**Obtener recursos de una suscripción:**
```powershell
Get-AzRA-ResourcesBySubscriptionID -AccessToken $token -SubscriptionID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Obtener grupos y roles de un usuario:**
```powershell
Get-AzRA-RolesGroupsByEmail -AccessToken $graphToken -Email "usuario@dominio.com"
```

## 🔐 Autenticación

Necesitas tokens de acceso válidos para las respectivas APIs:

**API de Azure Management:** `https://management.azure.com/`

**API de Microsoft Graph:** `https://graph.microsoft.com/`

Usa herramientas como `az account get-access-token` o adquiere tokens mediante el método que quieras/puedas.

### Configuración de Tokens

```powershell
# Importar módulo
Import-Module .\AzRA.psd1

# Obtener token de Azure Management (usando Azure CLI)
$azToken = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Obtener token de Microsoft Graph
$graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
```

## 📚 Reconocimiento Interno (Azure/M365)

### Funciones Disponibles

#### Autenticación
- `Request-AzRA-Nonce` - Solicitar nonce de Azure AD para un tenant

#### API de Azure Management
- `Get-AzRA-Subscriptions` - Listar todas las suscripciones accesibles
- `Get-AzRA-ResourcesBySubscriptionID` - Listar recursos de una suscripción
- `Get-AzRA-RoleAssignment` - Obtener permisos para un recurso

#### API de Microsoft Graph
- `Get-AzRA-Users` - Listar todos los usuarios (con paginación)
- `Get-AzRA-EnterpriseApplications` - Listar registros de aplicaciones (con paginación)
- `Get-AzRA-AppRoleAssignment` - Obtener asignaciones de roles de una aplicación
- `Get-AzRA-RolesGroupsByEmail` - Obtener membresías de grupos y roles de usuario (con paginación)
- `Invoke-AzRA-APIRequest` - Hacer peticiones personalizadas a cualquier endpoint de Azure o Microsoft Graph

#### Módulo Az (requiere Connect-AzAccount)
- `Get-AzRA-DeploymentParameterSecrets` - Auditar el historial de deployments buscando credenciales en texto claro

#### API de Azure Management — Automation
- `Get-AzRA-AutomationRunbooks` - Descargar y escanear Runbooks de Azure Automation buscando credenciales hardcodeadas

#### API de Azure Management — Logic Apps
- `Get-AzRA-LogicApps` - Enumerar Logic Apps y escanear definiciones, parámetros y acciones HTTP en busca de secretos y superficie de ataque

### Ejemplos por Función

#### 1. Request-AzRA-Nonce
Solicitar un nonce de Azure AD para un tenant específico.

```powershell
# Usando dominio
$nonce = Request-AzRA-Nonce -TenantID 'contoso.onmicrosoft.com'
Write-Output "Nonce obtenido: $nonce"

# Usando GUID del tenant
$nonce = Request-AzRA-Nonce -TenantID '12345678-1234-1234-1234-123456789abc'
```

#### 2. Get-AzRA-Subscriptions
Listar todas las suscripciones de Azure accesibles.

```powershell
# Obtener todas las suscripciones
$subs = Get-AzRA-Subscriptions -AccessToken $azToken

# Mostrar información básica
$subs | Select-Object subscriptionId, displayName, state

# Filtrar solo suscripciones activas
$subs | Where-Object {$_.state -eq 'Enabled'} | Select-Object displayName
```

#### 3. Get-AzRA-ResourcesBySubscriptionID
Listar todos los recursos dentro de una suscripción.

```powershell
# Obtener recursos de una suscripción específica
$resources = Get-AzRA-ResourcesBySubscriptionID -AccessToken $azToken -SubscriptionID 'b413826f-108d-4049-8c11-d52d5d348768'

# Filtrar solo máquinas virtuales
$vms = $resources | Where-Object {$_.type -eq 'Microsoft.Compute/virtualMachines'}
$vms | Select-Object name, location, resourceGroup

# Agrupar recursos por tipo
$resources | Group-Object type | Select-Object Count, Name | Sort-Object Count -Descending
```

#### 4. Get-AzRA-RoleAssignment
Obtener permisos y asignaciones de roles para un recurso.

```powershell
# Obtener permisos de un resource group
$rgPath = '/subscriptions/xxx-xxx-xxx/resourceGroups/Production'
$permissions = Get-AzRA-RoleAssignment -AccessToken $azToken -ResourcePath $rgPath

# Obtener permisos de una VM específica
$vmPath = '/subscriptions/b413826f-108d-4049-8c11-d52d5d348768/resourceGroups/Test/providers/Microsoft.Compute/virtualMachines/myVM'
$vmPerms = Get-AzRA-RoleAssignment -AccessToken $azToken -ResourcePath $vmPath
$vmPerms | Select-Object actions, notActions
```

#### 5. Get-AzRA-Users
Listar todos los usuarios del tenant con paginación automática.

```powershell
# Obtener todos los usuarios
$users = Get-AzRA-Users -AccessToken $graphToken

# Buscar administradores
$admins = $users | Where-Object {$_.userPrincipalName -like "*admin*"}
$admins | Select-Object userPrincipalName, displayName, mail

# Filtrar usuarios por dominio
$users | Where-Object {$_.userPrincipalName -like "*@contoso.com"} | Select-Object displayName, mail

# Contar usuarios totales
Write-Output "Total de usuarios: $($users.Count)"
```

#### 6. Get-AzRA-EnterpriseApplications
Listar todas las aplicaciones empresariales (registros de aplicación).

```powershell
# Obtener todas las aplicaciones
$apps = Get-AzRA-EnterpriseApplications -AccessToken $graphToken

# Mostrar información básica
$apps | Select-Object displayName, appId, publisherDomain

# Buscar aplicaciones por nombre
$apps | Where-Object {$_.displayName -like "*Microsoft*"} | Select-Object displayName, appId

# Contar aplicaciones
Write-Output "Total de aplicaciones: $($apps.Count)"
```

#### 7. Get-AzRA-AppRoleAssignment
Obtener asignaciones de roles de aplicación para un service principal.

```powershell
# Obtener role assignments de un service principal
$spId = '2830a3fe-846b-4008-b8e5-bbe6255488a8'
$roleAssignments = Get-AzRA-AppRoleAssignment -AccessToken $graphToken -ServicePrincipalId $spId

# Mostrar asignaciones
$roleAssignments | Select-Object principalDisplayName, principalType, appRoleId
```

#### 8. Get-AzRA-RolesGroupsByEmail
Obtener todos los grupos y roles de directorio de un usuario.

```powershell
# Obtener membresías de un usuario
$userGroups = Get-AzRA-RolesGroupsByEmail -AccessToken $graphToken -Email 'usuario@contoso.com'

# Filtrar solo grupos
$groups = $userGroups | Where-Object {$_.'@odata.type' -eq '#microsoft.graph.group'}
$groups | Select-Object displayName, mail

# Filtrar solo roles de directorio
$roles = $userGroups | Where-Object {$_.'@odata.type' -eq '#microsoft.graph.directoryRole'}
$roles | Select-Object displayName, description

# Contar membresías totales
Write-Output "Total de grupos/roles: $($userGroups.Count)"
```

#### 9. Invoke-AzRA-APIRequest
Hacer peticiones personalizadas a cualquier endpoint de Azure o Microsoft Graph.

```powershell
# Petición personalizada a Azure Management API
$customUri = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$result = Invoke-AzRA-APIRequest -AccessToken $azToken -Uri $customUri

# Petición a Microsoft Graph con paginación
$customGraphUri = 'https://graph.microsoft.com/v1.0/groups'
$groups = Invoke-AzRA-APIRequest -AccessToken $graphToken -Uri $customGraphUri -EnablePagination
$groups | Select-Object displayName, mail

# Petición a un endpoint específico de Graph
$deviceUri = 'https://graph.microsoft.com/v1.0/devices'
$devices = Invoke-AzRA-APIRequest -AccessToken $graphToken -Uri $deviceUri -EnablePagination
```

### Ejemplo de flujo de enumeración

```powershell
# 1. Importar módulo
Import-Module .\AzRA.psd1

# 2. Obtener tokens
$azToken = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
$graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

# 3. Enumerar suscripciones
$subs = Get-AzRA-Subscriptions -AccessToken $azToken
Write-Output "Suscripciones encontradas: $($subs.Count)"

# 4. Enumerar recursos de cada suscripción
foreach ($sub in $subs) {
    Write-Output "`nAnalizando suscripción: $($sub.displayName)"
    $resources = Get-AzRA-ResourcesBySubscriptionID -AccessToken $azToken -SubscriptionID $sub.subscriptionId
    Write-Output "  Recursos encontrados: $($resources.Count)"

    # Mostrar resumen por tipo
    $resources | Group-Object type | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table
}

# 5. Enumerar usuarios
$users = Get-AzRA-Users -AccessToken $graphToken
Write-Output "`nUsuarios encontrados: $($users.Count)"

# 6. Buscar usuarios privilegiados
$privilegedUsers = $users | Where-Object {
    $_.userPrincipalName -like "*admin*" -or
    $_.displayName -like "*admin*"
}
Write-Output "Usuarios potencialmente privilegiados: $($privilegedUsers.Count)"
$privilegedUsers | Select-Object userPrincipalName, displayName | Format-Table

# 7. Enumerar aplicaciones
$apps = Get-AzRA-EnterpriseApplications -AccessToken $graphToken
Write-Output "`nAplicaciones encontradas: $($apps.Count)"
```

#### 10. Get-AzRA-DeploymentParameterSecrets

Audita el historial de deployments de Azure buscando parámetros ARM que contengan credenciales o secretos en texto claro.

**Cómo funciona:**

1. Verifica que existe una sesión Az activa (`Connect-AzAccount`)
2. Itera sobre todas las suscripciones accesibles (o una específica)
3. Por cada suscripción → resource groups → deployments
4. Inspecciona `$dep.Parameters.Keys` buscando coincidencias con keywords (`password`, `secret`, `key`, `token`, etc.)
5. Filtra parámetros de tipo `SecureString` y valores falsos positivos (`null`, `true`, `false`, `none`...)
6. Devuelve los hallazgos al pipeline como objetos y opcionalmente los exporta a CSV

**Retry automático:** ante errores HTTP 429 (throttling) o errores transitorios 5xx, reintenta automáticamente con backoff lineal (espera `RetryDelaySec × intento`).

**Permisos requeridos:**
- `Microsoft.Resources/deployments/read`
- `Microsoft.Resources/subscriptions/resourceGroups/read`

```powershell
# Escanear todas las suscripciones
Connect-AzAccount
Get-AzRA-DeploymentParameterSecrets

# Escanear solo una suscripción
Get-AzRA-DeploymentParameterSecrets -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Exportar hallazgos a CSV (nombre auto-generado con timestamp)
Get-AzRA-DeploymentParameterSecrets -OutputPath 'C:\Reports'
# → C:\Reports\AzRA-DeploymentSecrets_20250406-1530.csv

# Exportar CSV y volcar todos los deployments en JSON para revisión manual
Get-AzRA-DeploymentParameterSecrets -OutputPath 'C:\Reports' -DumpRaw
# → C:\Reports\AzRA-DeploymentSecrets_20250406-1530.csv
# → C:\Reports\DeploymentTemplatesRawDump\<Suscripcion>\<ResourceGroup>\<Deployment>.json

# Filtrar por resource group
Get-AzRA-DeploymentParameterSecrets | Where-Object { $_.'Grupo de recursos' -eq 'Production' }

# Keywords personalizadas
Get-AzRA-DeploymentParameterSecrets -Keywords @('connectionstring', 'storageaccountkey', 'sas')

# Ajustar reintentos ante throttling
Get-AzRA-DeploymentParameterSecrets -MaxRetries 5 -RetryDelaySec 10
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción concreta. Si se omite, escanea todas |
| `-Keywords` | `string[]` | Lista de keywords para buscar en nombres de parámetros. Default: `password, secret, admin, key, pwd, cred, token, auth` |
| `-OutputPath` | `string` | Carpeta de salida. El CSV se genera con timestamp automático |
| `-DumpRaw` | `switch` | Vuelca los objetos raw de cada deployment como JSON. Requiere `-OutputPath` |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Campos de cada hallazgo (CSV y pipeline):**

| Campo | Descripción |
|---|---|
| `Nombre suscripcion` | Nombre de la suscripción |
| `ID suscripcion` | GUID de la suscripción |
| `Grupo de recursos` | Resource group donde está el deployment |
| `Deployment Name` | Nombre del deployment |
| `Parametros` | JSON con `Name`, `Value` y `Type` del parámetro encontrado |

**Estructura del dump raw (`-DumpRaw`):**

```
<OutputPath>/
  DeploymentTemplatesRawDump/
    <Suscripcion>/
      <ResourceGroup>/
        <DeploymentName>.json    ← objeto completo de Get-AzResourceGroupDeployment
```

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y autenticar
Import-Module .\AzRA.psd1
Connect-AzAccount

# 2. Buscar credenciales en historial de deployments
$secrets = Get-AzRA-DeploymentParameterSecrets -OutputPath 'C:\Reports\secrets.csv'
Write-Output "Hallazgos encontrados: $($secrets.Count)"

# 3. Ver hallazgos agrupados por suscripción
$secrets | Group-Object 'Nombre suscripcion' | Select-Object Count, Name | Sort-Object Count -Descending

# 4. Extraer solo los valores (para revisión manual)
$secrets | ForEach-Object { $_.Parametros | ConvertFrom-Json } | Select-Object Name, Value, Type
```

#### 11. Get-AzRA-AutomationRunbooks

Enumera todas las cuentas de Azure Automation accesibles, descarga el código fuente de cada Runbook y opcionalmente escanea el contenido buscando credenciales hardcodeadas.

**Cómo funciona:**

1. Itera sobre todas las suscripciones accesibles (o una específica)
2. Por cada suscripción enumera todas las Automation Accounts via Azure Management API
3. Por cada cuenta obtiene la lista de Runbooks (con paginación automática)
4. Descarga el contenido de cada Runbook con retry automático ante throttling
5. Opcionalmente guarda los archivos en disco con jerarquía por suscripción y cuenta
6. Opcionalmente escanea el contenido buscando asignaciones de credenciales en texto claro
7. Devuelve un objeto por Runbook al pipeline

**Retry automático:** ante errores HTTP 429 (throttling) o errores transitorios 5xx, reintenta automáticamente con backoff lineal.

**Permisos requeridos:**
- `Microsoft.Automation/automationAccounts/read`
- `Microsoft.Automation/automationAccounts/runbooks/read`
- `Microsoft.Automation/automationAccounts/runbooks/content/read`

```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Enumerar todos los Runbooks (solo metadatos al pipeline)
Get-AzRA-AutomationRunbooks -AccessToken $token

# Escanear solo una suscripción
Get-AzRA-AutomationRunbooks -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Descargar archivos y exportar CSV de metadatos
Get-AzRA-AutomationRunbooks -AccessToken $token -OutputPath 'C:\Audit'
# → C:\Audit\AutomationRunbooks\<Suscripcion>\<Cuenta>\<Runbook>.ps1
# → C:\Audit\AzRA-AutomationRunbooks_20250406-1530.csv

# Descargar y escanear credenciales hardcodeadas
Get-AzRA-AutomationRunbooks -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
# → C:\Audit\AzRA-AutomationRunbooks-Secrets_20250406-1530.csv

# Filtrar en pipeline solo los Runbooks con secrets
Get-AzRA-AutomationRunbooks -AccessToken $token -ScanSecrets |
    Where-Object { $_.HasSecrets } |
    Select-Object RunbookName, AutomationAccount, SecretFindings

# Keywords personalizadas
Get-AzRA-AutomationRunbooks -AccessToken $token -ScanSecrets `
    -Keywords @('storageaccountkey', 'sqlpassword', 'clientsecret')
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-AccessToken` | `string` | Token Bearer de Azure Management API (**obligatorio**) |
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción. Si se omite, escanea todas |
| `-OutputPath` | `string` | Carpeta de salida para archivos y CSVs (nombres auto-generados con timestamp) |
| `-ScanSecrets` | `switch` | Activa el scanner de credenciales hardcodeadas en el contenido |
| `-Keywords` | `string[]` | Keywords para detectar asignaciones sensibles. Default: `password, secret, key, token, credential, sas, connectionstring...` |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Objeto devuelto por Runbook (pipeline):**

| Campo | Descripción |
|---|---|
| `SubscriptionId` / `SubscriptionName` | Suscripción donde está la cuenta |
| `AutomationAccount` | Nombre de la Automation Account |
| `ResourceGroup` | Resource group de la cuenta |
| `RunbookName` | Nombre del Runbook |
| `RunbookType` | Tipo: `PowerShell`, `PowerShell72`, `Python3`, etc. |
| `RunbookState` | Estado: `Published`, `Draft` |
| `LastModified` | Fecha de última modificación |
| `ContentSizeBytes` | Tamaño del contenido en bytes |
| `FilePath` | Ruta del archivo guardado (`$null` si no se usó `-OutputPath`) |
| `SecretFindings` | Array de findings (`Keyword`, `Line`, `MatchedLine`). Vacío si `-ScanSecrets` no activo |
| `HasSecrets` | `$true` si se encontró algún finding |

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  AutomationRunbooks/
    <Suscripcion>/
      <AutomationAccount>/
        <Runbook>.ps1 / .py / .txt    ← extensión según RunbookType
  AzRA-AutomationRunbooks_<timestamp>.csv
  AzRA-AutomationRunbooks-Secrets_<timestamp>.csv   ← solo si -ScanSecrets
```

**Scanner de secrets (`-ScanSecrets`):**

Busca asignaciones del patrón `keyword = "valor"` o `keyword: 'valor'` (case-insensitive). Filtra automáticamente variables PowerShell (`$variable`) y valores triviales (`null`, `true`, `$null`) para reducir falsos positivos.

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo
Import-Module .\AzRA.psd1

# 2. Obtener token
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# 3. Escaneo completo con descarga y búsqueda de secrets
$runbooks = Get-AzRA-AutomationRunbooks -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
Write-Output "Runbooks encontrados: $($runbooks.Count)"

# 4. Ver resumen de secrets por cuenta
$runbooks | Where-Object { $_.HasSecrets } |
    Group-Object AutomationAccount |
    Select-Object Name, Count |
    Sort-Object Count -Descending

# 5. Ver todos los findings en detalle
$runbooks | Where-Object { $_.HasSecrets } | ForEach-Object {
    Write-Output "`n[$($_.AutomationAccount)] $($_.RunbookName)"
    $_.SecretFindings | ForEach-Object {
        Write-Output "  Line $($_.Line) [$($_.Keyword)]: $($_.MatchedLine)"
    }
}
```

#### 13. Get-AzRA-LogicApps

Enumera todas las Logic Apps accesibles, descarga su definición completa (triggers, acciones, parámetros del workflow) y opcionalmente las escanea en busca de credenciales hardcodeadas, endpoints expuestos y configuraciones sensibles.

**Cómo funciona:**

1. Itera sobre todas las suscripciones accesibles (o una específica)
2. Lista todas las Logic Apps de cada suscripción via Azure Management API (con paginación)
3. Descarga la definición completa de cada Logic App con retry automático ante throttling
4. Opcionalmente vuelca el JSON completo a disco en jerarquía por suscripción y RG
5. Opcionalmente escanea 4 fuentes en busca de información sensible (ver abajo)
6. Opcionalmente recupera y analiza el historial de versiones de cada Logic App
7. Devuelve un objeto por Logic App al pipeline con metadatos de superficie de ataque

**Retry automático:** ante errores HTTP 429 (throttling) o errores transitorios 5xx, reintenta con backoff lineal.

**Permisos requeridos:**
- `Microsoft.Logic/workflows/read`

```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Enumerar todas las Logic Apps (metadatos y superficie de ataque al pipeline)
Get-AzRA-LogicApps -AccessToken $token

# Escanear solo una suscripción
Get-AzRA-LogicApps -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Volcar JSONs y exportar CSV de metadatos
Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit'
# → C:\Audit\LogicAppsRawDump\<Suscripcion>\<ResourceGroup>\<LogicApp>.json
# → C:\Audit\AzRA-LogicApps_20250406-1530.csv

# Escaneo completo con búsqueda de secrets
Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
# → C:\Audit\AzRA-LogicApps-Secrets_20250406-1530.csv

# Incluir historial de versiones en el análisis
Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets -IncludeVersions
# → C:\Audit\LogicAppsRawDump\<Sub>\<RG>\<LogicApp>_versions.json

# Filtrar Logic Apps con triggers expuestos al exterior (tipo Request)
Get-AzRA-LogicApps -AccessToken $token |
    Where-Object { $_.HasExposedTrigger } |
    Select-Object LogicAppName, ResourceGroup, TriggerTypes, ExposedEndpoints

# Filtrar Logic Apps con parámetros SecureString (credenciales declaradas)
Get-AzRA-LogicApps -AccessToken $token |
    Where-Object { $_.SecureStringParamCount -gt 0 } |
    Select-Object LogicAppName, ResourceGroup, SecureStringParamCount

# Filtrar Logic Apps con findings de secrets
Get-AzRA-LogicApps -AccessToken $token -ScanSecrets |
    Where-Object { $_.HasSecrets } |
    Select-Object LogicAppName, ResourceGroup, SecretFindings

# Keywords personalizadas
Get-AzRA-LogicApps -AccessToken $token -ScanSecrets `
    -Keywords @('storageaccountkey', 'sqlconnection', 'apimsubscriptionkey')
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-AccessToken` | `string` | Token Bearer de Azure Management API (**obligatorio**) |
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción. Si se omite, escanea todas |
| `-OutputPath` | `string` | Carpeta de salida para JSONs y CSVs (nombres auto-generados con timestamp) |
| `-ScanSecrets` | `switch` | Activa el scanner de credenciales en 4 fuentes de la definición |
| `-IncludeVersions` | `switch` | Recupera y analiza el historial de versiones de cada Logic App |
| `-Keywords` | `string[]` | Keywords para la detección. Default: `password, secret, key, token, sas, bearer, authorization, ocp-apim...` |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Objeto devuelto por Logic App (pipeline):**

| Campo | Descripción |
|---|---|
| `SubscriptionId` / `SubscriptionName` | Suscripción donde está la Logic App |
| `ResourceGroup` | Resource group |
| `LogicAppName` | Nombre de la Logic App |
| `Location` | Región Azure |
| `State` | Estado: `Enabled`, `Disabled`, `Suspended` |
| `CreatedTime` / `ChangedTime` | Fechas de creación y última modificación |
| `TriggerCount` | Número total de triggers definidos |
| `TriggerTypes` | Tipos de trigger: `Request`, `Recurrence`, `ApiConnection`, etc. |
| `HasExposedTrigger` | `$true` si hay algún trigger de tipo `Request` (acepta conexiones HTTP entrantes) |
| `ExposedEndpoints` | IPs de `accessEndpointIpAddresses` si están configuradas |
| `ActionCount` | Número total de acciones (incluyendo anidadas en Scope/If/Foreach) |
| `HttpActionCount` | Número de acciones de tipo `Http` (llamadas salientes) |
| `HasHttpActions` | `$true` si hay acciones HTTP |
| `WorkflowParameterCount` | Total de parámetros del workflow |
| `SecureStringParamCount` | Parámetros de tipo `SecureString` |
| `PlaintextParamCount` | Parámetros con valor potencialmente visible |
| `Tags` | Hashtable de tags del recurso |
| `VersionCount` | Número de versiones en historial (`-1` si no se usó `-IncludeVersions`) |
| `SecretFindings` | Array de findings. Vacío si `-ScanSecrets` no activo |
| `HasSecrets` | `$true` si hay al menos un finding |
| `RawFilePath` | Ruta al JSON guardado (`$null` si no se usó `-OutputPath`) |

**Scanner de secrets (`-ScanSecrets`) — 4 fuentes:**

| Fuente | Qué analiza | Tipo de finding |
|---|---|---|
| `WorkflowParam` | `properties.parameters` — parámetros del workflow | `SecureString` (reportado siempre), `PlainText` (por keyword en el nombre) |
| `HttpAction` | Acciones de tipo `Http` — URI, headers, bloque `authentication`, body | `HttpUri`, `HttpHeader`, `HttpAuth`, `HttpBody` |
| `Action` | Cualquier otro tipo de acción — `inputs` serializado | `ActionInput` |
| `Trigger` | Triggers `ApiConnection` con inputs sospechosos | `TriggerInput` |
| `Tag` | Key + value de los tags del recurso | `TagValue` |

Los parámetros `SecureString` se reportan siempre aunque el valor esté enmascarado — su existencia ya es información relevante para el reconocimiento. Las expresiones dinámicas de Logic Apps (`@{body()}`, `@{outputs()}`) se filtran automáticamente para evitar falsos positivos.

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  LogicAppsRawDump/
    <Suscripcion>/
      <ResourceGroup>/
        <LogicApp>.json                 ← definición completa (properties.definition + parameters)
        <LogicApp>_versions.json        ← solo si -IncludeVersions
  AzRA-LogicApps_<timestamp>.csv
  AzRA-LogicApps-Secrets_<timestamp>.csv   ← solo si -ScanSecrets
```

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y obtener token
Import-Module .\AzRA.psd1
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# 2. Escaneo completo
$logicApps = Get-AzRA-LogicApps -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets -IncludeVersions
Write-Output "Logic Apps encontradas: $($logicApps.Count)"

# 3. Resumen de superficie de ataque
Write-Output "`n--- Triggers expuestos (Request) ---"
$logicApps | Where-Object { $_.HasExposedTrigger } |
    Select-Object LogicAppName, ResourceGroup, ExposedEndpoints | Format-Table

Write-Output "`n--- Logic Apps con acciones HTTP salientes ---"
$logicApps | Where-Object { $_.HasHttpActions } |
    Select-Object LogicAppName, ResourceGroup, HttpActionCount |
    Sort-Object HttpActionCount -Descending | Format-Table

# 4. Resumen de findings
Write-Output "`n--- Findings de credenciales ---"
$logicApps | Where-Object { $_.HasSecrets } |
    Group-Object ResourceGroup |
    Select-Object Name, Count | Sort-Object Count -Descending | Format-Table

# 5. Ver findings en detalle
$logicApps | Where-Object { $_.HasSecrets } | ForEach-Object {
    Write-Output "`n[$($_.ResourceGroup)] $($_.LogicAppName)"
    $_.SecretFindings | ForEach-Object {
        Write-Output "  [$($_.Source)/$($_.FindingType)] $($_.PropertyPath) → $($_.MatchedValue)"
    }
}
```

## 🌐 Reconocimiento Externo (O365)

### Funciones Disponibles

- `Invoke-O365EmailValidator` - Validar existencia de emails en Office 365

### Ejemplos de Uso

#### Invoke-O365EmailValidator

Valida direcciones de correo electrónico verificando su existencia en Office 365 sin enviar intentos de inicio de sesión.

**Uso básico:**
```powershell
# Validar emails desde un archivo
Invoke-O365EmailValidator -File emails.txt -Output validados.txt

# El archivo emails.txt debe contener un email por línea:
# usuario1@contoso.com
# usuario2@contoso.com
# usuario3@fabrikam.com

# El output solo contendrá los emails que existen en O365
```

**Petición API manual:**
```http
POST /common/GetCredentialType HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/json

{
  "username": "usuario@dominio.onmicrosoft.com",
  "isOtherIdpSupported": true
}
```

## 📝 Licencia

Ver [LICENSE](LICENSE)