# JameFirewall

Gestor profesional y unificado de reglas de Firewall de Windows para software y suites creativas.

## Arquitectura

JameFirewall sigue una **Arquitectura Hexagonal (Ports & Adapters / Clean Architecture)** con:
- **Core de Dominio (`src/jame_firewall/core/`)**: Casos de uso y entidades independientes de plataforma.
- **Adaptadores de Infraestructura (`src/jame_firewall/infrastructure/`)**: Interacción segura con el sistema operativo Windows (Netsh, PowerShell, Registro, Sistema de Archivos, UAC) sin uso de `shell=True` y con supresión de consolas (`CREATE_NO_WINDOW`).
- **Capa de Presentación (`src/jame_firewall/presentation/`)**: Interfaz gráfica en Tkinter/`ttkbootstrap` con despacho de concurrencia desacoplado mediante colas thread-safe.

## Desarrollo

### Requisitos
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

### Entorno y Comprobaciones de Calidad
```bash
# Sincronizar dependencias
uv sync

# Linter y Formato
uv run ruff check .
uv run ruff format --check .

# Tipado Estático Estricto
uv run mypy src tests

# Suite de Pruebas Multiplataforma
uv run pytest
```
