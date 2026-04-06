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