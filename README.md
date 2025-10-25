# Proyecto Anonymizer

## Descripción

Este proyecto implementa un sistema de anonimización de red utilizando Tor. El script `anonymazer.py` realiza verificaciones periódicas para asegurar que la conexión a través de Tor esté funcionando correctamente y que no haya fugas de DNS o IP.

## Características

- Verificación de estado de Tor
- Detección de fugas de DNS
- Verificación de anonimato de IP
- Monitoreo de tráfico no autorizado
- Activación de un interruptor de emergencia en caso de fallos de seguridad

## Requisitos

- Python 3.6+
- Bibliotecas: `psutil`, `urllib`, `subprocess`, `json`, `logging`, `random`, `sys`, `threading`, `time`, `socket`, `concurrent.futures`

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/anonymazer.git