"""Constantes de interfaz y textos centralizados para JameFirewall."""

# --- APLICACIÓN ---
APP_TITLE = "JameFirewall"
APP_GEOMETRY = "360x520"
APP_THEME = "darkly"
APP_ICON_RESOURCE = "res/icon/jamefirewall.ico"

# --- ETIQUETAS ---
LBL_SYSTEM_STATUS = "Estado del Sistema"
LBL_FIREWALL_CONTROL = "Control de Firewall"
LBL_ACTIVITY_LOG = "Registro de Actividad"
LBL_CONFIG_TITLE = "Configuración de Rutas - JameFirewall"
LBL_DIRECTORIES = "Directorios de búsqueda:"

# --- BOTONES ---
BTN_REFRESH = "ACTUALIZAR"
BTN_BLOCK = "ACTIVAR"
BTN_UNBLOCK = "DESACTIVAR"
BTN_CONFIG = "AJUSTES"
BTN_ADD = "+"
BTN_REMOVE = "-"
BTN_AUTODETECT = "AUTO-DETECTAR"
BTN_SAVE = "GUARDAR"
BTN_CANCEL = "CANCELAR"

# --- MENSAJES DE ESTADO ---
STATUS_LOADING = "Cargando..."
STATUS_PROTECTED = "Bloqueo configurado"
STATUS_PARTIAL = "Bloqueo parcial o pendiente"
STATUS_UNPROTECTED = "Deshabilitado"
STATUS_ERROR = "Error"
STATUS_REQ_ADMIN = "Sin Privilegios"

# --- PREFIJOS DE LOG ---
LOG_INFO = "[ INFO ]"
LOG_OK = "[  OK  ]"
LOG_WARN = "[ WARN ]"
LOG_ERR = "[ FAIL ]"

# --- TOOLTIPS ---
TT_BLOCK = "Crea reglas de firewall para bloquear las rutas establecidas"
TT_UNBLOCK = "Elimina las reglas propias; conserva reglas antiguas para revisión"
TT_REFRESH = "Verificar estado actual de las reglas"
TT_CONFIG = "Gestionar rutas de búsqueda de ejecutables"

# --- MENSAJES OPERATIVOS ---
MSG_ADMIN_CHECK = "Verificando privilegios de administrador..."
MSG_ADMIN_OK = "Privilegios confirmados"
MSG_NO_ADMIN = "Se requieren privilegios de administrador"
MSG_SCANNING = "Escaneando directorios en busca de ejecutables..."
MSG_SUCCESS_BLOCK = "Operación de bloqueo completada"
MSG_SUCCESS_UNBLOCK = "Operación de desbloqueo completada"
MSG_NO_EXE = "No se encontraron nuevos ejecutables"
MSG_NO_RULES = "No se encontraron reglas activas para eliminar"
MSG_CONF_SAVED = "Configuración guardada exitosamente"
MSG_PATHS_FOUND = "Nuevas rutas detectadas:"
MSG_NO_NEW_PATHS = "No se detectaron nuevas rutas de instalación"
