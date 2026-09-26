"""Doble de prueba en memoria para UACPort."""


class FakeUACAdapter:
    """Implementación de UACPort para pruebas deterministas."""

    def __init__(self, initial_is_admin: bool = True) -> None:
        self.admin_status: bool = initial_is_admin
        self.elevation_requested: bool = False
        self.elevation_success: bool = True

    def is_admin(self) -> bool:
        return self.admin_status

    def request_elevation(self) -> bool:
        self.elevation_requested = True
        if self.elevation_success:
            self.admin_status = True
            return True
        return False
