## 🎯 1. Propósito y Motivación (Why)
<!-- Explica con precisión el problema o requerimiento que resuelve este Pull Request. -->

## 🛠️ 2. Arquitectura de la Solución (What & How)
<!-- Detalla los cambios de diseño, módulos, puertos, entidades o adaptadores modificados. -->

## 🧪 3. Evidencia de Pruebas y Cobertura XP / TDD (Proof)
<!-- Documenta las pruebas unitarias o de integración creadas y adjunta la salida de verify_gate.sh. -->

## ⚠️ 4. Análisis de Riesgos y Regresiones
<!-- Evalúa si este cambio introduce Breaking Changes o posibles efectos colaterales en Windows. -->

## ✅ 5. Checklist de Calidad
- [ ] El título sigue estrictamente Conventional Commits 1.0.0 con un scope válido.
- [ ] No se utilizaron prefijos 'feat' para cambios exclusivos de tooling o CI.
- [ ] Se ejecutó ./verify_gate.sh superando el 100% de las pruebas, Ruff y Mypy Strict.
- [ ] Se preservó la arquitectura hexagonal y la cobertura de pruebas de dominio.
- [ ] No se incorporaron dependencias ni workarounds sin autorización arquitectónica.
