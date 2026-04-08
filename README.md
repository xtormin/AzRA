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
3. [⚡ Cheatsheet de Auditoría Rápida](#-cheatsheet-de-auditoría-rápida)
4. [📚 Reconocimiento Interno (Azure/M365)](#-reconocimiento-interno-azurem365)
   - [Funciones Disponibles](#funciones-disponibles)
   - [Ejemplos por Función](#ejemplos-por-función)
   - [Ejemplo de Flujo de Enumeración](#ejemplo-de-flujo-de-enumeración-completo)
5. [🌐 Reconocimiento Externo (O365)](#-reconocimiento-externo-o365)
   - [Funciones Disponibles](#funciones-disponibles-1)
   - [Ejemplos de Uso](#ejemplos-de-uso)
6. [📝 Licencia](#-licencia)

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

## ⚡ Cheatsheet de Auditoría Rápida

Secuencia de comandos para cubrir todos los vectores en una auditoría completa de Azure.
Definir `$CLIENTPATH` antes de empezar:

```powershell
$CLIENTPATH = "C:\Audits\Cliente_YYYYMMDD"
```

### 1. Az Module — Deployment History

```powershell
Connect-AzAccount
Get-AzRA-DeploymentParameterSecrets -OutputPath $CLIENTPATH -DumpRaw
```

> Requiere: `Connect-AzAccount` (credenciales interactivas o service principal).

### 2. Azure Management API — Recursos

```powershell
az login
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

Get-AzRA-AutomationRunbooks    -AccessToken $token -OutputPath $CLIENTPATH
Get-AzRA-LogicApps             -AccessToken $token -OutputPath $CLIENTPATH -ScanSecrets -IncludeVersions
Get-AzRA-StorageAccounts       -AccessToken $token -OutputPath $CLIENTPATH -ScanSecrets
Get-AzRA-KeyVaults             -AccessToken $token -OutputPath $CLIENTPATH
Get-AzRA-VirtualMachines       -AccessToken $token -OutputPath $CLIENTPATH
Get-AzRA-ContainerRegistries   -AccessToken $token -OutputPath $CLIENTPATH -ScanRepositories
Get-AzRA-FunctionApps          -AccessToken $token -OutputPath $CLIENTPATH -ScanSecrets -IncludeSlots
Get-AzRA-APIManagement         -AccessToken $token -OutputPath $CLIENTPATH -ScanSecrets
```

> Requiere: token ARM (`https://management.azure.com`).

### 3. Microsoft Graph — Entra ID

```powershell
$graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport -IncludeApps -IncludeConditionalAccess -OutputPath $CLIENTPATH
```

> Requiere: token Graph (`https://graph.microsoft.com`) con `Directory.Read.All`, `Reports.Read.All`, `Application.Read.All` y `Policy.Read.All`.

---

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

#### API de Azure Management — Storage
- `Get-AzRA-StorageAccounts` - Enumerar Storage Accounts y auditar misconfiguraciones de seguridad, contenedores públicos y claves de acceso

#### API de Azure Management — Key Vault
- `Get-AzRA-KeyVaults` - Enumerar Key Vaults y auditar misconfiguraciones de seguridad, configuración de recuperación, acceso de red y políticas de autorización

#### API de Azure Management — Virtual Machines
- `Get-AzRA-VirtualMachines` - Enumerar Virtual Machines y SQL VMs auditando exposición de red, extensiones peligrosas, cifrado de disco y configuración de seguridad

#### Microsoft Graph API — Entra ID
- `Get-AzRA-EntraID` - Auditar la configuración de seguridad del tenant de Entra ID: roles privilegiados, MFA, aplicaciones registradas, Conditional Access y políticas de directorio

#### API de Azure Management — Container Registry
- `Get-AzRA-ContainerRegistries` - Enumerar Azure Container Registries, auditar misconfiguraciones de seguridad, obtener tokens ACR de data plane, enumerar repositorios/tags/tamaños e interactuar con imágenes para docker pull

#### API de Azure Management — Function Apps / App Services
- `Get-AzRA-FunctionApps` - Enumerar Function Apps y App Services, auditar misconfiguraciones de seguridad y extraer app settings en texto claro (connection strings, API keys, client secrets)

#### API de Azure Management — API Management
- `Get-AzRA-APIManagement` - Enumerar servicios de API Management, auditar configuración de red y protocolos, y extraer subscription keys, named value secrets y credenciales de backends

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

#### 14. Get-AzRA-StorageAccounts

Enumera todas las Storage Accounts accesibles, evalúa cada una contra un conjunto de checks de seguridad críticos, altos e informativos, detecta contenedores con acceso público y opcionalmente extrae las claves de acceso.

**Cómo funciona:**

1. Itera sobre todas las suscripciones accesibles (o una específica)
2. Lista todas las Storage Accounts de cada suscripción (con paginación ARM)
3. Por cada cuenta evalúa los checks de seguridad directamente desde `properties`
4. Lista todos los contenedores blob de la cuenta (con paginación)
5. Para contenedores con acceso `Container` (nivel más alto): realiza **listado anónimo de blobs** sin token para demostrar el impacto real
6. Si `-ScanSecrets` y shared key access está habilitado: extrae las claves de acceso via POST `listKeys`
7. Opcionalmente vuelca los JSONs a disco y exporta CSVs con timestamp
8. Devuelve un objeto por cuenta al pipeline

**Retry automático:** ante errores HTTP 429 (throttling) o errores transitorios 5xx, reintenta con backoff lineal.

**Permisos requeridos:**
- `Microsoft.Storage/storageAccounts/read`
- `Microsoft.Storage/storageAccounts/blobServices/containers/read`
- `Microsoft.Storage/storageAccounts/listkeys/action` (solo para `-ScanSecrets`)

```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Enumerar todas las cuentas (metadatos y checks de seguridad al pipeline)
Get-AzRA-StorageAccounts -AccessToken $token

# Escanear solo una suscripción
Get-AzRA-StorageAccounts -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Volcar JSONs y exportar CSV de metadatos
Get-AzRA-StorageAccounts -AccessToken $token -OutputPath 'C:\Audit'
# → C:\Audit\StorageAccountsRawDump\<Suscripcion>\<Cuenta>\account.json
# → C:\Audit\StorageAccountsRawDump\<Suscripcion>\<Cuenta>\containers.json
# → C:\Audit\AzRA-StorageAccounts_20250406-1530.csv

# Extraer claves de acceso y connection strings
Get-AzRA-StorageAccounts -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
# → C:\Audit\AzRA-StorageAccounts-Secrets_20250406-1530.csv

# Filtrar cuentas con contenedores públicos (Container-level) y ver blobs expuestos
Get-AzRA-StorageAccounts -AccessToken $token |
    Where-Object { $_.HasPublicContainers } |
    Select-Object StorageAccountName, ResourceGroup, PublicContainerNames, AnonymousBlobCount, AnonymousBlobs

# Filtrar cuentas con mayor riesgo: sin firewall Y shared key habilitado
Get-AzRA-StorageAccounts -AccessToken $token |
    Where-Object { $_.NoFirewall -and $_.SharedKeyAccessEnabled } |
    Select-Object StorageAccountName, ResourceGroup, SubscriptionName

# Ver todas las misconfiguraciones ordenadas por criticidad
Get-AzRA-StorageAccounts -AccessToken $token |
    Select-Object StorageAccountName, ResourceGroup,
        HasPublicContainers, NoFirewall, SharedKeyAccessEnabled,
        HttpsNotEnforced, WeakTlsVersion, NoKeyExpirationPolicy |
    Sort-Object HasPublicContainers, NoFirewall -Descending | Format-Table
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-AccessToken` | `string` | Token Bearer de Azure Management API (**obligatorio**) |
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción. Si se omite, escanea todas |
| `-OutputPath` | `string` | Carpeta de salida para JSONs y CSVs (nombres auto-generados con timestamp) |
| `-ScanSecrets` | `switch` | Extrae las claves de acceso via `listKeys` (solo si shared key está habilitado) |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Checks de seguridad evaluados:**

| Severidad | Campo | Condición de riesgo |
|---|---|---|
| **Crítico** | `HasPublicContainers` | Algún contenedor con `publicAccess = "Container"` (listado + lectura anónima sin token) |
| **Crítico** | `HasBlobPublicContainers` | Algún contenedor con `publicAccess = "Blob"` (lectura si se conoce la URL) |
| **Crítico** | `NoFirewall` | `networkAcls.defaultAction = "Allow"` — cualquier IP puede acceder |
| **Crítico** | `SharedKeyAccessEnabled` | `allowSharedKeyAccess` no es `false` explícito (null = habilitado en cuentas antiguas) |
| **Alto** | `HttpsNotEnforced` | `supportsHttpsTrafficOnly = false` — permite tráfico HTTP sin cifrar. **Nota:** este campo es un flag de hallazgo (`true` = hay problema), no una copia directa de la propiedad Azure. Ver `HttpsTrafficOnlyEnabled` para el valor raw. |
| **Alto** | `WeakTlsVersion` | `minimumTlsVersion` es `TLS1_0` o `TLS1_1` |
| **Alto** | `NoKeyExpirationPolicy` | `keyPolicy` es null — las claves no tienen rotación obligatoria |
| **Alto** | `NoSasExpirationPolicy` | `sasPolicy` es null — los SAS tokens no tienen expiración forzada |
| **Alto** | `BlobPublicAccessAllowedAtAccount` | `allowBlobPublicAccess = true` — la cuenta permite contenedores públicos |
| **Info** | `FirewallBypassAzureServices` | El firewall permite bypass a servicios Azure |
| **Info** | `NoCustomerManagedKeys` | Cifrado con claves de Microsoft, no del cliente (`encryption.keySource`) |

**Objeto devuelto por cuenta (pipeline):**

| Campo | Descripción |
|---|---|
| `SubscriptionId` / `SubscriptionName` | Suscripción donde está la cuenta |
| `ResourceGroup` | Resource group |
| `StorageAccountName` | Nombre de la Storage Account |
| `Location`, `Kind`, `Sku` | Región, tipo y SKU |
| `CreationTime` | Fecha de creación |
| `HasPublicContainers` / `HasBlobPublicContainers` | Flags de contenedores públicos |
| `NoFirewall`, `SharedKeyAccessEnabled`, ... | Todos los checks de seguridad (bool) |
| `HttpsTrafficOnlyEnabled` | Espejo directo de `supportsHttpsTrafficOnly` de la API Azure. `$true` = HTTPS forzado (sin hallazgo). Usar este campo para comparar con el valor visto en el portal. |
| `MinimumTlsVersion`, `NetworkDefaultAction`, `EncryptionKeySource` | Valores raw de configuración |
| `ContainerCount` / `PublicContainerCount` / `BlobPublicContainerCount` | Conteos de contenedores |
| `PublicContainerNames` | Nombres de contenedores Container-level (comma-separated) |
| `AnonymousBlobCount` / `AnonymousBlobs` | Blobs encontrados via listado anónimo sin token |
| `KeyFindings` | Array de objetos `{KeyName, KeyValue, Permissions, ConnectionString}` si `-ScanSecrets` |
| `HasKeyFindings` | `$true` si se extrajeron claves |
| `RawFilePath` | Directorio del dump (`$null` si no se usó `-OutputPath`) |

**Listado anónimo de blobs:**

Cuando un contenedor tiene `publicAccess = "Container"`, la función llama automáticamente a `https://{account}.blob.core.windows.net/{container}?restype=container&comp=list&maxresults=100` **sin token de autenticación** para demostrar el impacto real. Los nombres de los blobs encontrados se incluyen en `AnonymousBlobs`. Si el listado falla (restricciones de red adicionales), se registra como `Write-Verbose` y no interrumpe el análisis.

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  StorageAccountsRawDump/
    <Suscripcion>/
      <StorageAccount>/
        account.json       ← ARM object completo de la cuenta
        containers.json    ← lista de contenedores con publicAccess
  AzRA-StorageAccounts_<timestamp>.csv
  AzRA-StorageAccounts-Secrets_<timestamp>.csv   ← solo si -ScanSecrets
```

**CSV de secrets (`-ScanSecrets`):**

| Campo | Descripción |
|---|---|
| `StorageAccountName` | Nombre de la cuenta |
| `KeyName` | `key1` o `key2` |
| `KeyValue` | Valor de la clave en texto claro |
| `Permissions` | Permisos: `Full` |
| `ConnectionString` | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net` |

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y obtener token
Import-Module .\AzRA.psd1
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# 2. Escaneo completo
$storage = Get-AzRA-StorageAccounts -AccessToken $token -OutputPath 'C:\Audit' -ScanSecrets
Write-Output "Storage Accounts encontradas: $($storage.Count)"

# 3. Resumen de criticidad
Write-Output "`n--- Contenedores públicos (CRÍTICO) ---"
$storage | Where-Object { $_.HasPublicContainers } |
    Select-Object StorageAccountName, ResourceGroup, PublicContainerNames, AnonymousBlobCount |
    Format-Table

Write-Output "`n--- Sin firewall (CRÍTICO) ---"
$storage | Where-Object { $_.NoFirewall } |
    Select-Object StorageAccountName, ResourceGroup, SubscriptionName | Format-Table

Write-Output "`n--- TLS débil o HTTPS no forzado (ALTO) ---"
# HttpsNotEnforced = true significa hallazgo (HTTPS NO forzado)
# HttpsTrafficOnlyEnabled = valor raw de la API (true = HTTPS forzado, sin problema)
$storage | Where-Object { $_.WeakTlsVersion -or $_.HttpsNotEnforced } |
    Select-Object StorageAccountName, MinimumTlsVersion, HttpsNotEnforced, HttpsTrafficOnlyEnabled | Format-Table

# 4. Ver claves extraídas
$storage | Where-Object { $_.HasKeyFindings } | ForEach-Object {
    Write-Output "`n[$($_.ResourceGroup)] $($_.StorageAccountName)"
    $_.KeyFindings | ForEach-Object {
        Write-Output "  $($_.KeyName): $($_.ConnectionString)"
    }
}
```

#### 15. Get-AzRA-KeyVaults

Enumera todos los Azure Key Vaults accesibles y los evalúa contra un conjunto de checks de seguridad críticos desde perspectiva de pentester, incluyendo configuración de recuperación, acceso de red, modelo de autorización y superficie de ataque expandida. Opcionalmente lista el inventario de secretos, claves y certificados vía Data Plane.

**Cómo funciona:**

1. Itera sobre todas las suscripciones accesibles (o una específica)
2. Lista todos los Key Vaults de cada suscripción (con paginación ARM). **Nota:** el listado inicial no incluye `properties` completas — se hace una llamada adicional por vault para obtener `accessPolicies`, `networkAcls`, `softDelete`, etc.
3. Por cada vault evalúa todos los checks de seguridad desde `properties`
4. Llama al endpoint de Diagnostic Settings (non-fatal) para detectar ausencia de audit logging
5. Si `-ScanSecrets` + `-VaultToken`: llama al Data Plane (`vault.azure.net`) para listar secretos, claves y certificados — solo metadatos (nombres, estado, expiración), **no valores**
6. Opcionalmente vuelca los JSONs a disco y exporta CSVs con timestamp

**Tokens necesarios:**
- `-AccessToken`: scope `https://management.azure.com/` — Management Plane
- `-VaultToken` (opcional, solo con `-ScanSecrets`): scope `https://vault.azure.net/` — Data Plane

**Permisos requeridos:**
- `Microsoft.KeyVault/vaults/read`
- `Microsoft.Insights/diagnosticSettings/read` (opcional — non-fatal si falta)
- Data Plane: `Secret List`, `Key List`, `Certificate List` (solo con `-ScanSecrets`)

```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Enumerar todos los vaults (management plane, sin data plane)
Get-AzRA-KeyVaults -AccessToken $token

# Escanear solo una suscripción
Get-AzRA-KeyVaults -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Volcar JSONs y exportar CSV
Get-AzRA-KeyVaults -AccessToken $token -OutputPath 'C:\Audit'
# → C:\Audit\KeyVaultsRawDump\<Suscripcion>\<Vault>\vault.json
# → C:\Audit\KeyVaultsRawDump\<Suscripcion>\<Vault>\diagnostics.json
# → C:\Audit\AzRA-KeyVaults_20250406-1530.csv

# Data plane: listar inventario de secretos/claves/certificados (requiere vault token)
$vaultToken = (az account get-access-token --resource https://vault.azure.net/ | ConvertFrom-Json).accessToken
Get-AzRA-KeyVaults -AccessToken $token -VaultToken $vaultToken -ScanSecrets -OutputPath 'C:\Audit'
# → C:\Audit\AzRA-KeyVaults-Secrets_20250406-1530.csv

# Filtrar vaults con misconfiguraciones críticas
Get-AzRA-KeyVaults -AccessToken $token |
    Where-Object { $_.NotRecoverable -or $_.PublicNetworkAccess -or $_.LegacyAccessPolicies } |
    Select-Object VaultName, ResourceGroup, NotRecoverable, PublicNetworkAccess, LegacyAccessPolicies

# Filtrar vaults con access policies excesivamente permisivas
Get-AzRA-KeyVaults -AccessToken $token |
    Where-Object { $_.OverlyPermissiveAccessPolicies } |
    Select-Object VaultName, ResourceGroup, AccessPolicyCount, RbacEnabled

# Filtrar vaults que expanden la superficie de ataque (deployment/disk/template)
Get-AzRA-KeyVaults -AccessToken $token |
    Where-Object { $_.EnabledForDeployment -or $_.EnabledForTemplateDeployment } |
    Select-Object VaultName, ResourceGroup, EnabledForDeployment, EnabledForTemplateDeployment

# Filtrar por secretos expirados (solo con -ScanSecrets -VaultToken)
Get-AzRA-KeyVaults -AccessToken $token -VaultToken $vaultToken -ScanSecrets |
    Where-Object { $_.HasExpiredSecrets } |
    Select-Object VaultName, ResourceGroup, SecretCount
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-AccessToken` | `string` | Token Bearer de Azure Management API (**obligatorio**) |
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción. Si se omite, escanea todas |
| `-OutputPath` | `string` | Carpeta de salida para JSONs y CSVs (nombres auto-generados con timestamp) |
| `-VaultToken` | `string` | Token Bearer de Key Vault Data Plane (`https://vault.azure.net/`). Requerido con `-ScanSecrets` |
| `-ScanSecrets` | `switch` | Activa el listado de secretos/claves/certificados via Data Plane (requiere `-VaultToken`) |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Checks de seguridad evaluados:**

| Severidad | Campo | Condición de riesgo |
|---|---|---|
| **Crítico** | `NotRecoverable` | `SoftDeleteDisabled` OR `PurgeProtectionDisabled` — los secretos se pueden eliminar permanentemente |
| **Crítico** | `SoftDeleteDisabled` | `enableSoftDelete != true` — sin periodo de retención ante borrado accidental/malicioso |
| **Crítico** | `PurgeProtectionDisabled` | `enablePurgeProtection != true` — borrado definitivo posible sin esperar retención |
| **Crítico** | `PublicNetworkAccess` | Red pública habilitada (`Enabled`) Y sin firewall (`networkAcls.defaultAction = Allow`) |
| **Crítico** | `LegacyAccessPolicies` | `enableRbacAuthorization != true` — usa Access Policies (vault-based), no RBAC de Azure |
| **Alto** | `OverlyPermissiveAccessPolicies` | Alguna policy tiene `"all"` o ≥ 8 permisos en secrets/keys/certificates |
| **Alto** | `EnabledForDeployment` | Las VMs pueden recuperar secretos del vault como parte de su provisioning |
| **Alto** | `EnabledForDiskEncryption` | El servicio Azure Disk Encryption puede leer claves del vault |
| **Alto** | `EnabledForTemplateDeployment` | Los ARM templates pueden recuperar secretos durante el despliegue |
| **Alto** | `WeakSoftDeleteRetention` | `softDeleteRetentionInDays < 30` — ventana de recuperación insuficiente |
| **Alto** | `NoFirewall` | `networkAcls.defaultAction = Allow` — sin restricción de red configurada |
| **Alto** | `NoDiagnosticSettings` | Sin diagnostic settings — no hay audit logging de accesos al vault |
| **Info** | `FirewallBypassAzureServices` | El firewall permite bypass a Azure Services |
| **Info** | `NoPrivateEndpoint` | Sin private endpoint configurado |
| **Info** | `StandardSku` | SKU Standard en lugar de Premium (sin HSM hardware) |

**Objeto devuelto por vault (pipeline):**

| Campo | Descripción |
|---|---|
| `SubscriptionId` / `SubscriptionName` | Suscripción |
| `ResourceGroup` | Resource group |
| `VaultName`, `Location`, `Sku`, `VaultUri`, `TenantId` | Identidad del vault |
| `NotRecoverable`, `SoftDeleteDisabled`, `PurgeProtectionDisabled` | Checks críticos de recuperación |
| `PublicNetworkAccess`, `LegacyAccessPolicies` | Checks críticos de acceso |
| `OverlyPermissiveAccessPolicies`, `EnabledForDeployment/DiskEncryption/TemplateDeployment` | Checks altos |
| `WeakSoftDeleteRetention`, `NoFirewall`, `NoDiagnosticSettings` | Checks altos |
| `FirewallBypassAzureServices`, `NoPrivateEndpoint`, `StandardSku` | Checks informativos |
| `SoftDeleteRetentionDays`, `NetworkDefaultAction`, `NetworkBypass` | Valores raw de configuración |
| `AccessPolicyCount`, `RbacEnabled`, `PublicNetworkAccessRaw` | Valores raw de autorización |
| `SecretCount` | Número de secretos/claves/certificados (solo con `-ScanSecrets -VaultToken`) |
| `SecretItems` | Array de `{ItemType, ItemName, Enabled, Expires, ContentType}` |
| `HasExpiredSecrets` | `$true` si algún secreto/clave ha expirado |
| `RawFilePath` | Directorio del dump (`$null` si no se usó `-OutputPath`) |

**Nota sobre el token de Data Plane:**

El token de Azure Management API y el token de Key Vault Data Plane tienen **scopes distintos** y no son intercambiables. Para activar `-ScanSecrets` se necesitan ambos tokens:

```powershell
$token      = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
$vaultToken = (az account get-access-token --resource https://vault.azure.net/ | ConvertFrom-Json).accessToken
```

El Data Plane solo devuelve **metadatos** (nombre, estado enabled/disabled, fecha de expiración). Los valores reales de los secretos NO se recuperan.

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  KeyVaultsRawDump/
    <Suscripcion>/
      <VaultName>/
        vault.json           ← ARM object completo (ConvertTo-Json -Depth 20)
        diagnostics.json     ← diagnostic settings (si se obtuvo)
  AzRA-KeyVaults_<timestamp>.csv
  AzRA-KeyVaults-Secrets_<timestamp>.csv   ← solo si -ScanSecrets + -VaultToken
```

**CSV de data plane (`-ScanSecrets -VaultToken`):**

| Campo | Descripción |
|---|---|
| `VaultName` | Nombre del vault |
| `ItemType` | `secret`, `key` o `certificate` |
| `ItemName` | Nombre del item |
| `ItemId` | URI completo del item en el data plane |
| `Enabled` | `$true` / `$false` |
| `Expires` | Fecha de expiración (UTC) o `$null` si no tiene |
| `ContentType` | Content type del secreto (si aplica) |

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y obtener tokens
Import-Module .\AzRA.psd1
$token      = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
$vaultToken = (az account get-access-token --resource https://vault.azure.net/ | ConvertFrom-Json).accessToken

# 2. Escaneo completo con data plane
$vaults = Get-AzRA-KeyVaults -AccessToken $token -VaultToken $vaultToken -ScanSecrets -OutputPath 'C:\Audit'
Write-Output "Key Vaults encontrados: $($vaults.Count)"

# 3. Resumen por severidad
Write-Output "`n--- CRÍTICO: No recuperables ---"
$vaults | Where-Object { $_.NotRecoverable } |
    Select-Object VaultName, ResourceGroup, SoftDeleteDisabled, PurgeProtectionDisabled | Format-Table

Write-Output "`n--- CRÍTICO: Acceso de red público ---"
$vaults | Where-Object { $_.PublicNetworkAccess } |
    Select-Object VaultName, ResourceGroup, NetworkDefaultAction | Format-Table

Write-Output "`n--- CRÍTICO: Access Policies (no RBAC) ---"
$vaults | Where-Object { $_.LegacyAccessPolicies } |
    Select-Object VaultName, ResourceGroup, AccessPolicyCount, OverlyPermissiveAccessPolicies | Format-Table

Write-Output "`n--- ALTO: Superficie de ataque expandida ---"
$vaults | Where-Object { $_.EnabledForDeployment -or $_.EnabledForTemplateDeployment -or $_.EnabledForDiskEncryption } |
    Select-Object VaultName, ResourceGroup, EnabledForDeployment, EnabledForDiskEncryption, EnabledForTemplateDeployment | Format-Table

# 4. Inventario de secretos expirados
$vaults | Where-Object { $_.HasExpiredSecrets } | ForEach-Object {
    Write-Output "`n[$($_.ResourceGroup)] $($_.VaultName)"
    $_.SecretItems | Where-Object { $_.Expires -and $_.Expires -lt (Get-Date) } | ForEach-Object {
        Write-Output "  [$($_.ItemType)] $($_.ItemName) — expiró: $($_.Expires)"
    }
}
```

#### 16. Get-AzRA-VirtualMachines

Enumera todas las Azure Virtual Machines y SQL Server on Azure VMs (IaaS) accesibles, evalúa cada una contra checks de seguridad críticos y detecta exposición real de red correlacionando la cadena VM → NIC → IP Pública → NSG. Las SQL VMs se correlacionan automáticamente con su VM subyacente enriqueciendo el mismo objeto de resultado.

**Cómo funciona:**

1. Itera sobre todas las suscripciones accesibles (o una específica)
2. Pre-carga el índice de SQL VMs por suscripción (una sola llamada API) para correlación posterior
3. Lista todas las Compute VMs de la suscripción (con paginación ARM)
4. Por cada VM:
   - Lista las extensiones instaladas
   - Resuelve la cadena NIC → Public IP para detectar IPs públicas reales
   - Obtiene reglas NSG asociadas a cada NIC para evaluar puertos abiertos (RDP, SSH, WinRM, SQL)
   - Correlaciona con el índice de SQL VMs usando el ARM ID
   - Si `-IncludeInstanceView`: llama al endpoint `/instanceView` para obtener `PowerState` y detalles del OS
5. Evalúa todos los checks de seguridad
6. Opcionalmente vuelca JSON a disco y exporta CSV

**Retry automático:** ante errores HTTP 429 (throttling) o errores transitorios 5xx, reintenta con backoff lineal.

**Permisos requeridos:**
- `Microsoft.Compute/virtualMachines/read`
- `Microsoft.Compute/virtualMachines/extensions/read`
- `Microsoft.SqlVirtualMachine/sqlVirtualMachines/read`
- `Microsoft.Network/networkInterfaces/read`
- `Microsoft.Network/publicIPAddresses/read`
- `Microsoft.Network/networkSecurityGroups/read`

```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Enumerar todas las VMs (checks de seguridad y exposición de red al pipeline)
Get-AzRA-VirtualMachines -AccessToken $token

# Escanear solo una suscripción
Get-AzRA-VirtualMachines -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Volcar JSONs y exportar CSV
Get-AzRA-VirtualMachines -AccessToken $token -OutputPath 'C:\Audit'
# → C:\Audit\VirtualMachinesRawDump\<Suscripcion>\<VM>\vm.json
# → C:\Audit\VirtualMachinesRawDump\<Suscripcion>\<VM>\extensions.json
# → C:\Audit\VirtualMachinesRawDump\<Suscripcion>\<VM>\network.json
# → C:\Audit\VirtualMachinesRawDump\<Suscripcion>\<VM>\sqlvm.json  (si SQL VM)
# → C:\Audit\AzRA-VirtualMachines_20250406-1530.csv

# Con instance view (PowerState + OS name — más lento a escala)
Get-AzRA-VirtualMachines -AccessToken $token -IncludeInstanceView

# Filtrar VMs con RDP o SSH expuesto a internet
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.RdpExposed -or $_.SshExposed } |
    Select-Object VmName, ResourceGroup, OsType, PublicIpAddresses, OpenInboundPorts

# Filtrar VMs con extensiones de RCE instaladas
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.CustomScriptExtension -or $_.RunCommandExtension } |
    Select-Object VmName, ResourceGroup, InstalledExtensions

# Filtrar VMs con IP pública y sin NSG (exposición desconocida)
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.HasPublicIp -and $_.OpenInboundPorts -eq 'unknown (no NSG)' } |
    Select-Object VmName, ResourceGroup, PublicIpAddresses

# Filtrar SQL VMs con conectividad pública o auth mixta
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.IsSqlVm -and ($_.SqlPublicConnectivity -or $_.SqlMixedAuthEnabled) } |
    Select-Object VmName, ResourceGroup, SqlImageSku, SqlConnectivity, PublicIpAddresses

# VMs sin identidad administrada (usan credenciales almacenadas)
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.NoManagedIdentity } |
    Select-Object VmName, ResourceGroup, OsType, ManagedIdentityType

# Ver todas las misconfiguraciones críticas
Get-AzRA-VirtualMachines -AccessToken $token |
    Where-Object { $_.HasPublicIp -or $_.CustomScriptExtension -or $_.OsDiskNotEncrypted } |
    Select-Object VmName, ResourceGroup, HasPublicIp, RdpExposed, SshExposed,
        CustomScriptExtension, OsDiskNotEncrypted |
    Sort-Object HasPublicIp, RdpExposed -Descending | Format-Table
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-AccessToken` | `string` | Token Bearer de Azure Management API (**obligatorio**) |
| `-SubscriptionId` | `string` | Limita el escaneo a una suscripción. Si se omite, escanea todas |
| `-OutputPath` | `string` | Carpeta de salida para JSONs y CSV (nombre auto-generado con timestamp) |
| `-IncludeInstanceView` | `switch` | Activa la llamada adicional `/instanceView` por VM para obtener `PowerState` y detalles del OS. Desactivado por defecto (coste significativo a escala) |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Checks de seguridad evaluados:**

| Severidad | Campo | Condición de riesgo |
|---|---|---|
| **Crítico** | `HasPublicIp` | La VM tiene al menos una IP pública asignada |
| **Crítico** | `RdpExposed` | IP pública + NSG permite inbound puerto 3389 desde 0.0.0.0/0 |
| **Crítico** | `SshExposed` | IP pública + NSG permite inbound puerto 22 desde 0.0.0.0/0 |
| **Crítico** | `WinRmExposed` | IP pública + NSG permite inbound puertos 5985/5986 desde internet |
| **Crítico** | `SqlPortExposed` | IP pública + NSG permite inbound puerto 1433 desde internet |
| **Crítico** | `CustomScriptExtension` | Extension `CustomScriptExtension` instalada — puede ejecutar scripts arbitrarios |
| **Crítico** | `RunCommandExtension` | Extension `RunCommandWindows/Linux` instalada — RCE directo |
| **Crítico** | `SqlMixedAuthEnabled` | SQL VM con autenticación mixta (SQL auth habilitada, no solo Windows) |
| **Crítico** | `SqlPublicConnectivity` | SQL VM con `sqlConnectivity = "PUBLIC"` — SQL Server accesible desde internet |
| **Alto** | `OsDiskNotEncrypted` | Disco OS sin Customer-Managed Key (CMK) asignado |
| **Alto** | `DataDiskNotEncrypted` | Algún disco de datos sin CMK |
| **Alto** | `EncryptionAtHostDisabled` | Cifrado a nivel de hipervisor no habilitado (discos temporales sin cifrar) |
| **Alto** | `SecureBootDisabled` | Secure Boot no habilitado (Trusted Launch no configurado) |
| **Alto** | `VtpmDisabled` | Virtual TPM no habilitado |
| **Alto** | `AadLoginNotConfigured` | Extension AAD Login no instalada — sin autenticación centralizada con MFA |
| **Alto** | `NoManagedIdentity` | Sin identidad administrada — la VM usa credenciales almacenadas |
| **Alto** | `BootDiagnosticsEnabled` | Boot diagnostics activo (escritura a storage account no cifrado con CMK) |
| **Alto** | `SqlEolVersion` | SQL VM con versión EOL: SQL Server 2008, 2012 o 2014 |
| **Alto** | `SqlNoBackup` | SQL VM sin configuración de backup automático |
| **Alto** | `MmaInstalled` | Microsoft Monitoring Agent / OMS Agent instalado |
| **Info** | `NoTags` | Sin tags — dificulta inventario y atribución |
| **Info** | `IsSpotInstance` | VM de tipo Spot (puede ser eviccionada) |
| **Info** | `EphemeralOsDisk` | Disco OS efímero (sin persistencia) |
| **Info** | `SingleNic` | Una sola interfaz de red |

**Objeto devuelto por VM (pipeline):**

| Campo | Descripción |
|---|---|
| `SubscriptionId` / `SubscriptionName` | Suscripción |
| `ResourceGroup` | Resource group |
| `VmName`, `VmId`, `Location`, `OsType`, `VmSize` | Identidad de la VM |
| `OsImagePublisher`, `OsImageOffer`, `OsImageSku` | Imagen del OS |
| `PowerState`, `OsName` | Estado de encendido y nombre del OS (solo con `-IncludeInstanceView`) |
| `ProvisioningState` | Estado de aprovisionamiento |
| `HasPublicIp`, `RdpExposed`, `SshExposed`, `WinRmExposed`, `SqlPortExposed` | Checks críticos de red |
| `CustomScriptExtension`, `RunCommandExtension` | Checks críticos de extensiones |
| `SqlMixedAuthEnabled`, `SqlPublicConnectivity` | Checks críticos de SQL |
| `OsDiskNotEncrypted`, `DataDiskNotEncrypted`, `EncryptionAtHostDisabled` | Checks altos de cifrado |
| `SecureBootDisabled`, `VtpmDisabled` | Checks altos de Trusted Launch |
| `AadLoginNotConfigured`, `NoManagedIdentity`, `BootDiagnosticsEnabled`, `MmaInstalled` | Checks altos de identidad |
| `SqlEolVersion`, `SqlNoBackup` | Checks altos de SQL |
| `NoTags`, `IsSpotInstance`, `EphemeralOsDisk`, `SingleNic` | Checks informativos |
| `PublicIpAddresses` | IPs públicas asignadas (comma-separated) |
| `PrivateIpAddresses` | IPs privadas (comma-separated) |
| `NicCount` | Número de interfaces de red |
| `InstalledExtensions` | Tipos de extensiones instaladas (comma-separated) |
| `OpenInboundPorts` | Puertos abiertos desde internet (ej. `"22,3389"`) o `"unknown (no NSG)"` |
| `ManagedIdentityType` | `None`, `SystemAssigned`, `UserAssigned` o `Both` |
| `DataDiskCount` | Número de discos de datos |
| `IsSqlVm` | `$true` si la VM tiene el SQL VM provider overlay |
| `SqlImageSku`, `SqlLicenseType`, `SqlConnectivity`, `SqlManagementMode` | Metadatos SQL (si `IsSqlVm`) |
| `RawFilePath` | Directorio del dump (`$null` si no se usó `-OutputPath`) |

**Correlación VM → NIC → IP Pública → NSG:**

La función resuelve automáticamente la cadena completa de recursos de red para cada VM. Por cada NIC en `networkProfile.networkInterfaces`:
1. Recupera la NIC completa via ARM ID
2. Sigue las referencias `publicIPAddress.id` para obtener las IPs públicas reales
3. Obtiene las reglas NSG asociadas a la NIC y evalúa puertos peligrosos

Si una VM tiene IP pública pero no tiene NSG asociada a ninguna NIC, `OpenInboundPorts` se marca como `"unknown (no NSG)"` para indicar que la exposición no pudo evaluarse (posiblemente solo protegida por Azure Firewall o sin protección).

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  VirtualMachinesRawDump/
    <Suscripcion>/
      <VmName>/
        vm.json            ← ARM object completo de la VM
        extensions.json    ← lista de extensiones instaladas
        network.json       ← NICs con IPs y NSGs
        sqlvm.json         ← SQL VM object (solo si IsSqlVm)
  AzRA-VirtualMachines_<timestamp>.csv
```

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y obtener token
Import-Module .\AzRA.psd1
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# 2. Escaneo completo con instance view
$vms = Get-AzRA-VirtualMachines -AccessToken $token -IncludeInstanceView -OutputPath 'C:\Audit'
Write-Output "VMs encontradas: $($vms.Count)"
Write-Output "SQL VMs: $(($vms | Where-Object { $_.IsSqlVm }).Count)"

# 3. Resumen de exposición de red
Write-Output "`n--- CRÍTICO: VMs con RDP/SSH abierto a internet ---"
$vms | Where-Object { $_.RdpExposed -or $_.SshExposed } |
    Select-Object VmName, ResourceGroup, OsType, PublicIpAddresses, OpenInboundPorts | Format-Table

# 4. Extensiones peligrosas
Write-Output "`n--- CRÍTICO: VMs con extensiones de ejecución remota ---"
$vms | Where-Object { $_.CustomScriptExtension -or $_.RunCommandExtension } |
    Select-Object VmName, ResourceGroup, InstalledExtensions | Format-Table

# 5. SQL VMs vulnerables
Write-Output "`n--- CRÍTICO: SQL VMs con conectividad pública o auth mixta ---"
$vms | Where-Object { $_.IsSqlVm -and ($_.SqlPublicConnectivity -or $_.SqlEolVersion) } |
    Select-Object VmName, ResourceGroup, SqlImageSku, SqlConnectivity | Format-Table

# 6. VMs con mayor superficie de ataque
$vms |
    Select-Object VmName, ResourceGroup,
        @{N='CriticalCount'; E={
            @($_.HasPublicIp, $_.RdpExposed, $_.SshExposed, $_.WinRmExposed,
              $_.CustomScriptExtension, $_.RunCommandExtension) |
            Where-Object { $_ -eq $true } | Measure-Object | Select-Object -Expand Count
        }} |
    Sort-Object CriticalCount -Descending | Format-Table
```

#### 17. Get-AzRA-EntraID

Audita la configuración de seguridad del tenant de Entra ID (Azure Active Directory) desde perspectiva de pentester. A diferencia del resto de funciones, devuelve un **único objeto por tenant** con colecciones de findings organizadas por severidad. Cubre usuarios privilegiados, configuración de MFA, aplicaciones registradas, políticas de Conditional Access y ajustes globales de directorio.

**Cómo funciona:**

1. Realiza las llamadas base con `Directory.Read.All`:
   - Información del tenant (nombre, dominios, licencias P1/P2)
   - Authorization Policy (quién puede registrar apps, invitar guests, dar consentimiento)
   - Security Defaults
   - Role definitions y role assignments (con expansión del principal en la misma llamada)
   - Lista completa de usuarios + `signInActivity` para detectar cuentas inactivas
   - Service Principals para identificar apps con roles privilegiados
2. Si `-IncludeMFAReport`: lee `/reports/authenticationMethods/userRegistrationDetails` para evaluar el estado de MFA de cada usuario
3. Si `-IncludeApps`: enumera todas las App Registrations y evalúa credenciales expiradas, apps sin propietario, apps multi-tenant y permisos Graph sensibles
4. Si `-IncludeConditionalAccess`: lee todas las CA policies y evalúa si la auth legacy está bloqueada, si se exige MFA a admins y usuarios, y si hay políticas en modo report-only
5. Cruza los datos entre colecciones (ej: Global Admins → MFA index) para findings combinados
6. Exporta CSVs y dump JSON raw si se especifica `-OutputPath`

**Token necesario:** Graph API — scope `https://graph.microsoft.com/`

**Permisos por módulo:**

| Switch | Permiso requerido | Qué analiza |
|---|---|---|
| (base, siempre) | `Directory.Read.All` | Tenant, roles, usuarios, SPs, authorization policy |
| `-IncludeMFAReport` | `Reports.Read.All` + `AuditLog.Read.All` | Estado MFA por usuario, admins sin MFA |
| `-IncludeApps` | `Application.Read.All` | App registrations: credenciales, propietarios, permisos |
| `-IncludeConditionalAccess` | `Policy.Read.All` | CA policies: legacy auth, MFA gaps, report-only |

Si alguna llamada devuelve 403, se emite `Write-Warning` con el permiso que falta y el análisis continúa con los datos disponibles.

```powershell
$graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

# Análisis base (solo Directory.Read.All)
Get-AzRA-EntraID -GraphToken $graphToken

# Análisis completo con todos los módulos
Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport -IncludeApps -IncludeConditionalAccess

# Con exportación a disco (CSVs + JSON raw dump)
Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport -IncludeApps -IncludeConditionalAccess -OutputPath 'C:\Audit'

# Solo una suscripción / tenant (el token ya define el scope del tenant)

# Ver Global Admins sin MFA (CRÍTICO)
$r = Get-AzRA-EntraID -GraphToken $graphToken -IncludeMFAReport
$r.GlobalAdminsWithoutMFA | Select-Object DisplayName, UserPrincipalName, MethodsRegistered

# Ver usuarios Guest con roles privilegiados (CRÍTICO)
$r.PrivilegedGuests | Select-Object DisplayName, UserPrincipalName, Roles

# Ver cuentas privilegiadas inactivas >90 días (ALTO)
$r.StalePrivilegedAccounts | Select-Object DisplayName, UserPrincipalName, LastSignIn, Roles

# Ver si legacy auth está bloqueada (CRÍTICO)
$r.LegacyAuthNotBlocked    # $true = RIESGO (no está bloqueada)

# Ver resumen de misconfiguraciones críticas y altas
$r | Select-Object TenantDisplayName, HasCriticalFindings, HasHighFindings,
    SecurityDefaultsDisabled, UsersCanRegisterApps, GuestInvitationNotRestricted,
    LegacyAuthNotBlocked, NoMFARequiredForAdmins, MFARegistrationRate

# Ver apps con permisos Graph sensibles (CRÍTICO)
$r.AppsWithBroadPermissions | Select-Object DisplayName, AppId, SensitivePermissions

# Ver CA policies en modo report-only (no aplicadas)
$r.CAPoliciesReportOnly | Select-Object DisplayName, State
```

**Parámetros:**

| Parámetro | Tipo | Descripción |
|---|---|---|
| `-GraphToken` | `string` | Token Bearer de Microsoft Graph API (**obligatorio**) |
| `-OutputPath` | `string` | Carpeta de salida para JSONs y CSVs (nombres auto-generados con timestamp) |
| `-IncludeMFAReport` | `switch` | Activa el análisis de estado MFA por usuario (requiere `Reports.Read.All`) |
| `-IncludeApps` | `switch` | Activa el análisis de App Registrations (requiere `Application.Read.All`) |
| `-IncludeConditionalAccess` | `switch` | Activa el análisis de CA policies (requiere `Policy.Read.All`) |
| `-MaxRetries` | `int` | Máximo de reintentos ante throttling/errores 5xx (1-10). Default: 3 |
| `-RetryDelaySec` | `int` | Segundos base entre reintentos, multiplicado por el número de intento (1-60). Default: 5 |

**Checks de seguridad evaluados:**

| Severidad | Campo | Condición de riesgo |
|---|---|---|
| **Crítico** | `GlobalAdminsWithoutMFA` | Global Administrators sin ningún método MFA registrado |
| **Crítico** | `PrivilegedGuests` | Usuarios de tipo Guest con roles privilegiados asignados |
| **Crítico** | `PrivilegedServicePrincipals` | Service Principals con roles privilegiados (Global Admin, Security Admin, etc.) |
| **Crítico** | `LegacyAuthNotBlocked` | Sin CA policy activa que bloquee `exchangeActiveSync` / `other` (auth legacy) |
| **Crítico** | `NoMFARequiredForAdmins` | Sin CA policy activa que exija MFA a roles privilegiados |
| **Crítico** | `AppsWithBroadPermissions` | Apps con permisos sensibles admin-consented: `Directory.ReadWrite.All`, `Mail.ReadWrite`, `Application.ReadWrite.All`, etc. |
| **Alto** | `SecurityDefaultsDisabled` | Security Defaults desactivadas — sin baseline de MFA/legacy auth |
| **Alto** | `UsersCanRegisterApps` | `allowedToCreateApps = true` — cualquier usuario puede registrar aplicaciones |
| **Alto** | `UsersCanConsentToApps` | Política de consent no restringida — usuarios pueden autorizar apps a acceder a sus datos |
| **Alto** | `GuestInvitationNotRestricted` | `allowInvitesFrom` permite invitación por usuarios no-admin |
| **Alto** | `AdminConsentWorkflowDisabled` | Sin flujo de aprobación para consent de apps — facilita illicit consent grant attacks |
| **Alto** | `StalePrivilegedAccounts` | Cuentas con rol privilegiado sin actividad en >90 días |
| **Alto** | `UsersWithoutMFA` | Usuarios sin ningún método MFA registrado |
| **Alto** | `UsersWithWeakMFA` | Usuarios con MFA solo por SMS/voz (vulnerable a SIM swapping) |
| **Alto** | `AppsWithExpiredCredentials` | Apps con `passwordCredentials` o `keyCredentials` expirados |
| **Alto** | `AppsWithoutOwners` | Apps registradas sin propietario asignado |
| **Alto** | `MultiTenantApps` | Apps con `signInAudience` externo al tenant — accesibles desde otros tenants |
| **Alto** | `CAPoliciesReportOnly` | CA policies en modo `reportOnly` — reportan pero no aplican restricciones |
| **Alto** | `NoCARequiringMFAForAllUsers` | Sin CA policy que exija MFA para todos los usuarios |

**Objeto devuelto por tenant:**

| Campo | Descripción |
|---|---|
| `TenantId`, `TenantDisplayName`, `TenantCreatedDateTime` | Identidad del tenant |
| `VerifiedDomains` | Array de dominios verificados |
| `TenantHasP1P2` | `$true` si el tenant tiene licencia Azure AD Premium P1 o P2 |
| `HasCriticalFindings` / `HasHighFindings` | Flags de resumen para filtrado rápido |
| `TotalUserCount`, `GuestCount`, `GlobalAdminCount` | Estadísticas del tenant |
| `MFARegistrationRate` | % de usuarios con MFA registrado (solo con `-IncludeMFAReport`) |
| `ExternalAppsCount` | Número de apps multi-tenant (solo con `-IncludeApps`) |
| `ActiveCAPoliciesCount` | CA policies en estado `enabled` (solo con `-IncludeConditionalAccess`) |
| `GlobalAdminsWithoutMFA` | Array de `{Id, DisplayName, UPN, MethodsRegistered}` |
| `PrivilegedGuests` | Array de `{Id, DisplayName, UPN, Roles}` |
| `PrivilegedServicePrincipals` | Array de `{Id, DisplayName, AppId, Roles}` |
| `StalePrivilegedAccounts` | Array de `{Id, DisplayName, UPN, LastSignIn, Roles}` |
| `UsersWithoutMFA` / `UsersWithWeakMFA` | Arrays de usuarios |
| `AppsWithBroadPermissions` | Array de `{DisplayName, AppId, SignInAudience, SensitivePermissions}` |
| `AppsWithExpiredCredentials` | Array de `{DisplayName, AppId, CredentialType, ExpiredOn}` |
| `GlobalAdmins` | Lista completa de Global Administrators |
| `AllPrivilegedRoleAssignments` | Todos los role assignments a roles de alta privilegio |
| `CAPoliciesReportOnly` | Políticas activas pero no aplicadas |

**Estructura de salida en disco (`-OutputPath`):**

```
<OutputPath>/
  EntraIDRawDump/
    tenant.json                          ← /organization object
    authorizationPolicy.json             ← authorization policy
    securityDefaults.json                ← security defaults enforcement policy
    roleAssignments.json                 ← todos los role assignments con principal
    conditionalAccessPolicies.json       ← CA policies (si -IncludeConditionalAccess)
    applications.json                    ← app registrations (si -IncludeApps)
    mfaRegistrationDetails.json          ← MFA report (si -IncludeMFAReport)
  AzRA-EntraID-Summary_<timestamp>.csv              ← 1 fila con todos los flags y conteos
  AzRA-EntraID-GlobalAdmins_<timestamp>.csv         ← lista de Global Admins
  AzRA-EntraID-PrivilegedUsers_<timestamp>.csv      ← todos los role assignments privilegiados
  AzRA-EntraID-MFA_<timestamp>.csv                  ← estado MFA de todos los usuarios
  AzRA-EntraID-Apps_<timestamp>.csv                 ← apps con checks de seguridad
  AzRA-EntraID-CAPolicies_<timestamp>.csv           ← CA policies con evaluación
```

**Permisos sensibles de Graph monitorizados (`-IncludeApps`):**

| Permiso | Por qué es crítico |
|---|---|
| `Directory.ReadWrite.All` | Modificar cualquier objeto del directorio |
| `Directory.Read.All` | Leer todo el directorio (usuarios, grupos, apps, roles) |
| `User.ReadWrite.All` | Modificar cualquier usuario del tenant |
| `Mail.ReadWrite` / `Mail.Read` | Leer y escribir todos los buzones de correo |
| `Group.ReadWrite.All` | Gestionar todos los grupos (incluyendo roles) |
| `Application.ReadWrite.All` | Crear y modificar aplicaciones — permite backdoors |
| `AppRoleAssignment.ReadWrite.All` | Asignar roles de aplicación — escalada de privilegios |
| `RoleManagement.ReadWrite.Directory` | Gestionar roles de directorio — acceso total |

### Ejemplo de flujo de enumeración completo

```powershell
# 1. Importar módulo y obtener token
Import-Module .\AzRA.psd1
$graphToken = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

# 2. Análisis completo
$r = Get-AzRA-EntraID -GraphToken $graphToken `
    -IncludeMFAReport -IncludeApps -IncludeConditionalAccess `
    -OutputPath 'C:\Audit' -Verbose

# 3. Resumen ejecutivo
Write-Output "Tenant: $($r.TenantDisplayName) ($($r.TenantId))"
Write-Output "Licencia P1/P2: $($r.TenantHasP1P2)"
Write-Output "Usuarios totales: $($r.TotalUserCount) | Guests: $($r.GuestCount)"
Write-Output "Global Admins: $($r.GlobalAdminCount)"
Write-Output "MFA registration rate: $($r.MFARegistrationRate)%"

# 4. Findings críticos
Write-Output "`n=== CRÍTICOS ==="

if ($r.GlobalAdminsWithoutMFA) {
    Write-Output "[!] Global Admins sin MFA:"
    $r.GlobalAdminsWithoutMFA | ForEach-Object { Write-Output "    $($_.UserPrincipalName)" }
}

if ($r.PrivilegedGuests) {
    Write-Output "[!] Guest users con roles privilegiados:"
    $r.PrivilegedGuests | ForEach-Object { Write-Output "    $($_.UserPrincipalName) → $($_.Roles)" }
}

if ($r.LegacyAuthNotBlocked) { Write-Output "[!] Legacy authentication NO está bloqueada" }
if ($r.NoMFARequiredForAdmins) { Write-Output "[!] No hay CA policy que exija MFA a admins" }

if ($r.AppsWithBroadPermissions) {
    Write-Output "[!] Apps con permisos Graph sensibles:"
    $r.AppsWithBroadPermissions | ForEach-Object {
        Write-Output "    $($_.DisplayName) → $($_.SensitivePermissions)"
    }
}

# 5. Findings altos
Write-Output "`n=== ALTOS ==="
if ($r.SecurityDefaultsDisabled) { Write-Output "[-] Security Defaults desactivadas" }
if ($r.UsersCanRegisterApps) { Write-Output "[-] Los usuarios pueden registrar aplicaciones" }
if ($r.GuestInvitationNotRestricted) { Write-Output "[-] Invitación de guests no restringida a admins" }

if ($r.StalePrivilegedAccounts) {
    Write-Output "[-] Cuentas privilegiadas sin actividad >90 días:"
    $r.StalePrivilegedAccounts | ForEach-Object {
        Write-Output "    $($_.UserPrincipalName) — último acceso: $($_.LastSignIn ?? 'nunca')"
    }
}

Write-Output "[-] Usuarios sin MFA: $($r.UsersWithoutMFA.Count)"
Write-Output "[-] Usuarios con MFA débil (SMS/voz): $($r.UsersWithWeakMFA.Count)"

# 6. Apps problemáticas
if ($r.AppsWithExpiredCredentials) {
    Write-Output "`n[-] Apps con credenciales expiradas:"
    $r.AppsWithExpiredCredentials | Select-Object DisplayName, CredentialType, ExpiredOn | Format-Table
}

if ($r.AppsWithoutOwners) {
    Write-Output "[-] Apps sin propietario: $($r.AppsWithoutOwners.Count)"
}
```

#### 18. Get-AzRA-ContainerRegistries

Enumera todos los Azure Container Registries (ACR) accesibles, evalúa misconfiguraciones de seguridad a nivel ARM, y opcionalmente realiza reconocimiento del data plane (repositorios, tags, tamaños de imagen) con selección interactiva para docker pull.

**Cómo funciona:**

La función opera en dos capas diferenciadas:

**Capa ARM** (token `management.azure.com`, siempre activa):
- Lista todos los registries en las subscripciones accesibles via `Microsoft.ContainerRegistry/registries`
- Evalúa checks críticos, altos e informativos sobre la configuración del registry
- Intenta obtener credenciales de admin si `adminUserEnabled` está activo
- Recupera la configuración de Diagnostic Settings para verificar si se registran logs

**Capa data plane** (`-ScanRepositories`):
- Intercambia el ARM token por un ACR refresh token via `POST https://{registry}.azurecr.io/oauth2/exchange` — equivalente a `az acr login --expose-token`
- Obtiene access tokens con scope específico (`registry:catalog:*`, `repository:{repo}:pull`)
- Enumera repositorios (`/v2/_catalog`, paginado via header `Link`)
- Para cada repositorio lista tags y calcula el **tamaño comprimido** de cada imagen sumando `config.size + layers[].size` del manifest v2
- Genera automáticamente un archivo `.txt` con todos los comandos `docker pull`

**Selección interactiva** (`-InteractivePull`):
- Muestra tabla con índice, imagen completa y tamaño antes de ejecutar ningún pull
- El usuario selecciona por índice (ej: `1,3`), `all` o `none`
- Si el total supera 5 GB, pide confirmación adicional
- Si Docker no está disponible, genera igualmente el archivo de comandos

**Checks de seguridad (ARM):**

| Severidad | Check | Descripción |
|---|---|---|
| Crítico | `AnonymousPullEnabled` | Cualquier usuario puede hacer pull sin autenticación |
| Crítico | `AdminUserEnabled` | Usuario admin habilitado (credenciales estáticas) |
| Crítico | `PublicNetworkAccessEnabled` | Acceso público sin restricciones de red |
| Alto | `NoFirewallRules` | Sin reglas de firewall IP configuradas |
| Alto | `RetentionPolicyDisabled` | Sin política de retención de imágenes no etiquetadas |
| Alto | `ContentTrustDisabled` | Content Trust (firma de imágenes) no habilitado |
| Alto | `DiagnosticLogsDisabled` | Sin Diagnostic Settings configurados |
| Alto | `BasicSku` | SKU Basic no soporta content trust, private endpoints ni geo-replicación |
| Info | `NoPrivateEndpoints` | Sin Private Endpoints configurados |
| Info | `ZoneRedundancyDisabled` | Sin redundancia de zona habilitada |

**Permisos necesarios:**
- `Microsoft.ContainerRegistry/registries/read` — base
- `Microsoft.ContainerRegistry/registries/listCredentials/action` — solo si admin user habilitado
- `microsoft.insights/diagnosticSettings/read` — opcional, para check de logs

**Uso básico:**
```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Solo checks de seguridad ARM
Get-AzRA-ContainerRegistries -AccessToken $token

# Una sola subscripción
Get-AzRA-ContainerRegistries -AccessToken $token -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
```

**Enumeración de repositorios y generación de pull commands:**
```powershell
# Enumera repos/tags/tamaños y genera AzRA-ACR-PullCommands_<timestamp>.txt
Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories -OutputPath 'C:\Audit'
```

**Selección interactiva de imágenes:**
```powershell
# Muestra tabla, pregunta qué hacer pull, ejecuta docker pull para los seleccionados
Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories -InteractivePull
```

Ejemplo de salida interactiva:
```
[*] Seleccion interactiva de imagenes para docker pull

  Registry: miacr.azurecr.io  (3 imagenes, 2.4 GB total)

  Idx  Imagen                                                       Tamano
  ---  ------                                                       ------
  [1]  hasura/graphql-engine:v2.38.1                                1.2 GB
  [2]  myapp/backend:latest                                         800 MB
  [3]  myapp/frontend:v1.0                                          400 MB

Introduce los indices a descargar (ej: 1,3), 'all' para todos, 'none' para omitir:
  > 1,2

  [~] Ejecutando: docker pull miacr.azurecr.io/hasura/graphql-engine:v2.38.1
  [~] Ejecutando: docker pull miacr.azurecr.io/myapp/backend:latest
```

**Filtrado de resultados:**
```powershell
$result = Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories

# Registries con admin user habilitado o pull anónimo
$result | Where-Object { $_.AdminUserEnabled -or $_.AnonymousPullEnabled }

# Registries donde se obtuvo acceso al data plane
$result | Where-Object { $_.DataPlaneAccessible -eq $true } |
    Select-Object RegistryName, RepositoryCount, TotalImageSizeGB

# Ver detalle de repos de un registry
$result | Where-Object { $_.RegistryName -eq 'miacr' } |
    ForEach-Object {
        $_.Repositories | Format-Table RepositoryName, TagCount,
            @{N='SizeMB'; E={[Math]::Round($_.TotalSizeBytes/1MB, 1)}}
    }

# Solo registries con findings críticos
$result | Where-Object { $_.HasCriticalFindings } |
    Select-Object LoginServer, AnonymousPullEnabled, AdminUserEnabled, PublicNetworkAccessEnabled
```

**Flujo de reconocimiento (replica el proceso manual):**
```powershell
# Equivalente a:
#   az acr list
#   az acr login --expose-token --name $server
#   docker login $server -u 00000000-0000-0000-0000-000000000000 -p $token
#   az acr repository list --name $server
#   az acr repository show-tags --name $server --repository "hasura/graphql-engine"
#   docker pull $server/hasura/graphql-engine:v2.38.1

$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken
$result = Get-AzRA-ContainerRegistries -AccessToken $token -ScanRepositories -InteractivePull -OutputPath 'C:\Audit'
```

**Archivos generados (`-OutputPath`):**
```
C:\Audit\
  AzRA-ContainerRegistries_<timestamp>.csv           # 1 fila por registry, todos los checks booleanos
  AzRA-ContainerRegistries-Repos_<timestamp>.csv     # 1 fila por imagen (registry, repo, tag, tamano)
  AzRA-ACR-PullCommands_<timestamp>.txt              # Comandos docker pull para todas las imagenes
  ContainerRegistriesRawDump\
    <SubscriptionName>\
      <RegistryName>\
        registry.json         # Objeto ARM completo del registry
        diagnostics.json      # Estado de Diagnostic Settings
        repositories.json     # Repos, tags y tamanios (si -ScanRepositories)
```

#### 19. Get-AzRA-FunctionApps

Enumera todas las Function Apps y App Services, evalúa misconfiguraciones de seguridad a nivel ARM y opcionalmente extrae todas las app settings en texto claro. Es uno de los vectores más rentables en auditorías Azure: las app settings contienen habitualmente connection strings, storage account keys, client secrets de Entra ID, API keys de terceros y tokens hardcodeados.

**Cómo funciona:**

**Checks ARM** (siempre activos):
- Recupera todas las apps via `Microsoft.Web/sites` (incluye Function Apps, Web Apps y API Apps)
- Para cada app obtiene la configuración de sitio (`/config/web`) y las auth settings V2 (`/config/authsettingsV2`)
- Evalúa restricciones IP (`ipSecurityRestrictions`) y acceso SCM/Kudu (`scmIpSecurityRestrictions`)
- Detecta managed identities y VNet integration

**Extracción de app settings** (`-ScanSecrets`):
- Llama a `POST /config/appsettings/list` por cada app — endpoint ARM que devuelve todos los pares clave/valor en texto claro
- Con `-IncludeSlots` repite la extracción en cada slot de staging (producción y staging frecuentemente comparten las mismas secrets con menor restricción de red)

**Checks de seguridad:**

| Severidad | Check | Descripción |
|---|---|---|
| Crítico | `HttpsOnlyDisabled` | `httpsOnly != true` — permite tráfico HTTP sin cifrar |
| Crítico | `AuthDisabled + NoIpRestrictions` | App pública sin autenticación ni restricciones de red |
| Crítico | `PublicScmAccess` | Consola Kudu accesible públicamente sin restricciones (potencial RCE con publish profile) |
| Crítico | `HasSecrets` | Se extrajeron app settings en texto claro (`-ScanSecrets`) |
| Alto | `MinTlsWeak` | TLS mínimo 1.0 o 1.1 |
| Alto | `FtpEnabled` | FTP no deshabilitado (`ftpsState` no es `Disabled`) |
| Alto | `RemoteDebuggingEnabled` | Depuración remota activa |
| Alto | `AlwaysOnDisabled` | Function App sin Always On (cold starts, puede evadir monitoreo) |
| Alto | `HasManagedIdentity + NoVNet` | Managed Identity sin VNet integration (acceso directo a internet) |
| Info | `SlotCount` | Número de slots de staging existentes |
| Info | `VNetIntegrated` | Si la app tiene VNet integration |

**Permisos necesarios:**
- `Microsoft.Web/sites/read` — base
- `Microsoft.Web/sites/config/list/action` — para `-ScanSecrets`
- `Microsoft.Web/sites/slots/read` — para `-IncludeSlots`

**Uso básico:**
```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Solo checks de seguridad ARM
Get-AzRA-FunctionApps -AccessToken $token

# Extracción de app settings (el vector principal)
Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'

# Con slots de staging
Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets -IncludeSlots -OutputPath 'C:\Audit'
```

**Filtrado de resultados:**
```powershell
$result = Get-AzRA-FunctionApps -AccessToken $token -ScanSecrets

# Mostrar todas las secrets extraidas
$result | Where-Object { $_.HasSecrets } | ForEach-Object {
    Write-Output "=== $($_.AppName) ==="
    $_.Secrets | ForEach-Object { Write-Output "  $($_.Name) = $($_.Value)" }
}

# Apps con Kudu público
$result | Where-Object { $_.PublicScmAccess } |
    Select-Object AppName, ResourceGroup, DefaultHostName

# Solo Function Apps con auth deshabilitada
$result | Where-Object { $_.IsFunctionApp -and $_.AuthDisabled } |
    Select-Object AppName, DefaultHostName, NoIpRestrictions

# Apps con managed identity (mapeo de posibles rutas de escalada)
$result | Where-Object { $_.HasManagedIdentity } |
    Select-Object AppName, ManagedIdentityType, ManagedIdentityPrincipalId, VNetIntegrated
```

**Archivos generados (`-OutputPath`):**
```
C:\Audit\
  AzRA-FunctionApps_<timestamp>.csv           # 1 fila por app, todos los checks booleanos
  AzRA-FunctionApps-Secrets_<timestamp>.csv   # 1 fila por app setting extraida (si -ScanSecrets)
  FunctionAppsRawDump\
    <SubscriptionName>\
      <AppName>\
        app.json          # Objeto ARM completo
        appsettings.json  # App settings raw (si -ScanSecrets)
        slots.json        # Lista de slots (si -IncludeSlots)
```

---

#### 20. Get-AzRA-APIManagement

Enumera todos los servicios de Azure API Management, evalúa misconfiguraciones de seguridad y opcionalmente extrae tres categorías de secretos: subscription keys, named values de tipo secret y credenciales de backends. APIM actúa como gateway centralizado y frecuentemente almacena credenciales de todos los servicios backend a los que llama.

**Cómo funciona:**

**Checks ARM** (siempre activos):
- Lista servicios via `Microsoft.ApiManagement/service`
- Evalúa `virtualNetworkType` (None/External/Internal) — sin VNet = exposición pública completa
- Lee `customProperties` para detectar TLS 1.0/1.1, SSL 3.0 y cifrado 3DES
- Comprueba Diagnostic Settings para verificar si se registran logs
- El endpoint de gestión directa (puerto 3443) queda expuesto cuando no hay VNet integration

**Extracción de secretos** (`-ScanSecrets`), en orden de valor ofensivo:
1. **Named Values secretos**: enumera todos los Named Values con `secret=true` y llama a `listValue` por cada uno — contienen API keys, tokens y passwords usados en políticas del gateway
2. **Subscription Keys**: lista todas las suscripciones APIM y llama a `listSecrets` para obtener `primaryKey` y `secondaryKey` — permiten llamar a las APIs publicadas
3. **Backend credentials**: enumera todos los backends y extrae credenciales de `authorization` (basic auth) y headers personalizados (frecuentemente `Authorization: Bearer <token>`)

**Checks de seguridad:**

| Severidad | Check | Descripción |
|---|---|---|
| Crítico | `PublicNetworkEnabled` | `virtualNetworkType = None` — gateway expuesto sin VNet |
| Crítico | `DirectMgmtEndpointOpen` | Puerto 3443 accesible desde internet (sin VNet) |
| Crítico | `DeveloperPortalEnabled` | Developer portal accesible públicamente |
| Crítico | `HasSecrets` | Se extrajeron secretos (`-ScanSecrets`) |
| Alto | `LegacyProtocolsEnabled` | TLS 1.0, TLS 1.1 o SSL 3.0 habilitados |
| Alto | `WeakCiphersEnabled` | Cifrado 3DES habilitado |
| Alto | `SkuConsumption` | SKU Consumption sin soporte para VNet integration |
| Alto | `DiagnosticLogsDisabled` | Sin Diagnostic Settings configurados |
| Info | `HasCustomDomains` | Dominios personalizados configurados |
| Info | `VirtualNetworkType` | Tipo de integración de red (None/External/Internal) |

**Permisos necesarios:**
- `Microsoft.ApiManagement/service/read` — base
- `Microsoft.ApiManagement/service/subscriptions/listSecrets/action` — subscription keys
- `Microsoft.ApiManagement/service/namedValues/listValue/action` — named value secrets
- `microsoft.insights/diagnosticSettings/read` — opcional

**Uso básico:**
```powershell
$token = (az account get-access-token --resource https://management.azure.com | ConvertFrom-Json).accessToken

# Solo checks de seguridad ARM
Get-AzRA-APIManagement -AccessToken $token

# Extracción completa de secretos
Get-AzRA-APIManagement -AccessToken $token -ScanSecrets -OutputPath 'C:\Audit'
```

**Filtrado de resultados:**
```powershell
$result = Get-AzRA-APIManagement -AccessToken $token -ScanSecrets

# Ver todos los secretos extraidos por tipo
$result | Where-Object { $_.HasSecrets } | ForEach-Object {
    Write-Output "=== $($_.ServiceName) - $($_.SecretCount) secretos ==="
    $_.Secrets | Format-Table SecretType, Name, Value
}

# Solo named values (API keys de terceros)
$result | ForEach-Object { $_.Secrets } |
    Where-Object { $_.SecretType -eq 'NamedValue' } |
    Format-Table ServiceName, Name, Value

# Subscription keys (para llamar a las APIs publicadas)
$result | ForEach-Object { $_.Secrets } |
    Where-Object { $_.SecretType -eq 'SubscriptionKey' } |
    Format-Table ServiceName, Name, Value

# Servicios con acceso público
$result | Where-Object { $_.PublicNetworkEnabled } |
    Select-Object ServiceName, GatewayUrl, ManagementApiUrl, DeveloperPortalUrl, Sku
```

**Archivos generados (`-OutputPath`):**
```
C:\Audit\
  AzRA-APIManagement_<timestamp>.csv           # 1 fila por servicio, checks booleanos
  AzRA-APIManagement-Secrets_<timestamp>.csv   # 1 fila por secreto extraido (si -ScanSecrets)
  APIManagementRawDump\
    <SubscriptionName>\
      <ServiceName>\
        service.json        # Objeto ARM completo del servicio
        namedValues.json    # Lista de Named Values (sin valores de secretos)
        subscriptions.json  # Lista de suscripciones APIM
        backends.json       # Definiciones de backends con credenciales
```

---

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