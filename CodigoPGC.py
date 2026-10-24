
import flet as ft
import flet_local_auth as fla
import sqlite3
import hashlib
import secrets
import base64
import os
from cryptography.fernet import Fernet, InvalidToken

BASE_DATOS = "biometria.db"
ITERACIONES = 600000


def conectar():
    conexion = sqlite3.connect(BASE_DATOS)
    conexion.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            nombre TEXT PRIMARY KEY,
            estado TEXT NOT NULL,
            sal BLOB NOT NULL,
            hash_contrasena BLOB NOT NULL,
            credencial_cifrada BLOB NOT NULL
        )
    """)
    conexion.commit()
    return conexion


def generar_hash(contrasena, sal):
    return hashlib.pbkdf2_hmac(
        "sha256",
        contrasena.encode("utf-8"),
        sal,
        ITERACIONES
    )


def generar_clave(contrasena, sal):
    clave = generar_hash(contrasena, sal)
    return base64.urlsafe_b64encode(clave)


def cifrar_credencial(contrasena, sal, credencial):
    clave = generar_clave(contrasena, sal)
    return Fernet(clave).encrypt(credencial)


def descifrar_credencial(contrasena, sal, cifrado):
    clave = generar_clave(contrasena, sal)
    return Fernet(clave).decrypt(cifrado)


def huella_texto(datos):
    return hashlib.sha256(datos).hexdigest()[:24]


def main(page: ft.Page):
    page.title = "Biometría Cancelable - U Cundinamarca"
    page.padding = 25
    page.scroll = ft.ScrollMode.AUTO

    conexion = conectar()

    nombre = ft.TextField(
        label="Nombre del usuario",
        width=350
    )

    contrasena = ft.TextField(
        label="Contraseña actual",
        password=True,
        can_reveal_password=True,
        width=350
    )

    nueva_contrasena = ft.TextField(
        label="Nueva contraseña",
        password=True,
        can_reveal_password=True,
        width=350
    )

    estado = ft.Text("Sistema listo para iniciar")
    total = ft.Text("Usuarios registrados: 0")
    lista = ft.Column(spacing=5)
    evidencias = ft.Column(spacing=8)

    def mostrar(mensaje):
        estado.value = mensaje
        page.update()

    def buscar_usuario(usuario):
        return conexion.execute(
            """
            SELECT estado, sal, hash_contrasena,
                   credencial_cifrada
            FROM usuarios
            WHERE nombre = ?
            """,
            (usuario,)
        ).fetchone()

    def verificar_contrasena(datos, clave):
        if not datos or not clave:
            return False

        hash_guardado = datos[2]
        hash_ingresado = generar_hash(clave, datos[1])

        return secrets.compare_digest(
            hash_guardado,
            hash_ingresado
        )

    def actualizar_lista():
        lista.controls.clear()

        registros = conexion.execute(
            "SELECT nombre, estado FROM usuarios ORDER BY nombre"
        ).fetchall()

        for usuario, estado_usuario in registros:
            lista.controls.append(
                ft.Text(usuario + " | " + estado_usuario)
            )

        total.value = (
            "Usuarios registrados: " + str(len(registros))
        )
        page.update()

    def registrar(e):
        usuario = nombre.value.strip()
        clave = contrasena.value

        if not usuario or not clave:
            mostrar("Escribe el nombre y la contraseña.")
            return

        if len(clave) < 8:
            mostrar("La contraseña debe tener al menos 8 caracteres.")
            return

        if buscar_usuario(usuario):
            mostrar("Ese usuario ya está registrado.")
            return

        sal = secrets.token_bytes(16)
        credencial = secrets.token_bytes(32)

        hash_clave = generar_hash(clave, sal)
        cifrado = cifrar_credencial(clave, sal, credencial)

        conexion.execute(
            """
            INSERT INTO usuarios
            (nombre, estado, sal, hash_contrasena,
             credencial_cifrada)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                usuario,
                "Activo",
                sal,
                hash_clave,
                cifrado
            )
        )
        conexion.commit()

        actualizar_lista()
        mostrar("Usuario registrado y credencial cifrada.")

    async def autenticar(e):
        usuario = nombre.value.strip()
        clave = contrasena.value

        if not usuario or not clave:
            mostrar("Escribe el nombre y la contraseña.")
            return

        datos = buscar_usuario(usuario)

        if not datos:
            mostrar("El usuario no está registrado.")
            return

        if datos[0] != "Activo":
            mostrar("La credencial está revocada.")
            return

        if not verificar_contrasena(datos, clave):
            mostrar("Contraseña incorrecta.")
            return

        try:
            descifrar_credencial(clave, datos[1], datos[3])

            auth = fla.LocalAuthentication()
            disponible = await auth.can_check_biometrics()

            if not disponible:
                mostrar(
                    "No hay autenticación biométrica disponible."
                )
                return

            resultado = await auth.authenticate(
                "Verifica tu identidad"
            )

            if resultado is False:
                mostrar("La autenticación biométrica falló.")
                return

            mostrar("Autenticación biométrica completada.")

        except InvalidToken:
            mostrar("No se pudo descifrar la credencial.")
        except Exception as error:
            mostrar(
                "Autenticación cancelada o fallida: " + str(error)
            )

    def revocar(e):
        usuario = nombre.value.strip()
        clave = contrasena.value

        datos = buscar_usuario(usuario) if usuario else None

        if not datos:
            mostrar("El usuario no está registrado.")
            return

        if datos[0] != "Activo":
            mostrar("La credencial ya está revocada.")
            return

        if not verificar_contrasena(datos, clave):
            mostrar("Contraseña incorrecta.")
            return

        conexion.execute(
            "UPDATE usuarios SET estado = ? WHERE nombre = ?",
            ("Revocada", usuario)
        )
        conexion.commit()

        actualizar_lista()
        mostrar("Credencial del usuario revocada.")

    def renovar(e):
        usuario = nombre.value.strip()
        clave_actual = contrasena.value
        clave_nueva = nueva_contrasena.value

        if not usuario or not clave_actual or not clave_nueva:
            mostrar(
                "Escribe el usuario y ambas contraseñas."
            )
            return

        if len(clave_nueva) < 8:
            mostrar("La nueva contraseña requiere 8 caracteres.")
            return

        datos = buscar_usuario(usuario)

        if not datos:
            mostrar("El usuario no está registrado.")
            return

        if not verificar_contrasena(datos, clave_actual):
            mostrar("La contraseña actual es incorrecta.")
            return

        sal_nueva = secrets.token_bytes(16)
        credencial_nueva = secrets.token_bytes(32)
        hash_nuevo = generar_hash(clave_nueva, sal_nueva)
        cifrado_nuevo = cifrar_credencial(
            clave_nueva, sal_nueva, credencial_nueva
        )

        cambio = datos[3] != cifrado_nuevo

        conexion.execute(
            """
            UPDATE usuarios
            SET estado = ?, sal = ?, hash_contrasena = ?,
                credencial_cifrada = ?
            WHERE nombre = ?
            """,
            (
                "Activo",
                sal_nueva,
                hash_nuevo,
                cifrado_nuevo,
                usuario
            )
        )
        conexion.commit()

        actualizar_lista()

        evidencias.controls.clear()
        evidencias.controls.append(
            ft.Text("RESULTADO DE LA RENOVACIÓN", weight=ft.FontWeight.BOLD)
        )
        evidencias.controls.append(
            ft.Text("Credencial anterior: " + huella_texto(datos[3]))
        )
        evidencias.controls.append(
            ft.Text("Credencial nueva: " + huella_texto(cifrado_nuevo))
        )
        evidencias.controls.append(
            ft.Text("¿Cambió la credencial?: " + str(cambio))
        )
        evidencias.controls.append(
            ft.Text("Estado final: Activo")
        )

        contrasena.value = ""
        nueva_contrasena.value = ""
        mostrar("Credencial renovada correctamente.")

    def consultar_seguridad(e):
        usuario = nombre.value.strip()

        if not usuario:
            mostrar("Escribe el nombre del usuario.")
            return

        datos = buscar_usuario(usuario)

        if not datos:
            mostrar("El usuario no está registrado.")
            return

        nombre_archivo = os.path.abspath(BASE_DATOS)
        hash_guardado = datos[2]
        cifrado = datos[3]

        evidencias.controls.clear()
        evidencias.controls.extend([
            ft.Text(
                "INFORME DE SEGURIDAD",
                size=18,
                weight=ft.FontWeight.BOLD
            ),
            ft.Text("Base de datos: " + nombre_archivo),
            ft.Text("Usuario: " + usuario),
            ft.Text("Estado: " + datos[0]),
            ft.Divider(),
            ft.Text("PROTECCIÓN DE CONTRASEÑA",
                    weight=ft.FontWeight.BOLD),
            ft.Text("Algoritmo: PBKDF2-HMAC-SHA256"),
            ft.Text("Iteraciones: " + str(ITERACIONES)),
            ft.Text("Sal aleatoria guardada: Sí"),
            ft.Text("Hash almacenado: " + hash_guardado.hex()[:32] + "..."),
            ft.Text("Contraseña original guardada: No"),
            ft.Divider(),
            ft.Text("CREDENCIAL CIFRADA",
                    weight=ft.FontWeight.BOLD),
            ft.Text("Cifrado: Fernet (AES)"),
            ft.Text("Datos cifrados: " + cifrado.decode("utf-8")[:48] + "..."),
            ft.Text("Identificador SHA-256: " + huella_texto(cifrado)),
            ft.Text(
                "Tamaño del dato cifrado: "
                + str(len(cifrado)) + " bytes"
            ),
            ft.Text("Ruta de SQLite comprobada: " +
                    str(os.path.exists(BASE_DATOS))),
            ft.Divider(),
            ft.Text(
                "Para verificar el descifrado, pulsa el botón "
                "'Probar cifrado'."
            )
        ])

        mostrar("Informe de seguridad consultado.")

    def probar_cifrado(e):
        usuario = nombre.value.strip()
        clave = contrasena.value

        datos = buscar_usuario(usuario) if usuario else None

        if not datos:
            mostrar("El usuario no está registrado.")
            return

        if not clave:
            mostrar("Escribe la contraseña actual para probar el cifrado.")
            return

        try:
            descifrada = descifrar_credencial(
                clave, datos[1], datos[3]
            )

            evidencias.controls.append(
                ft.Text(
                    "RESULTADO: descifrado correcto. "
                    "La credencial se recuperó con la contraseña.",
                    color="green"
                )
            )
            evidencias.controls.append(
                ft.Text(
                    "Longitud recuperada: "
                    + str(len(descifrada)) + " bytes"
                )
            )
            mostrar("Prueba de cifrado correcta.")

        except (InvalidToken, ValueError):
            evidencias.controls.append(
                ft.Text(
                    "RESULTADO: no se pudo descifrar. "
                    "Comprueba la contraseña.",
                    color="red"
                )
            )
            mostrar("Falló la prueba de cifrado.")

        page.update()

    def limpiar(e):
        nombre.value = ""
        contrasena.value = ""
        nueva_contrasena.value = ""
        mostrar("Campos limpiados.")

    page.add(
        ft.Text(
            "SISTEMA DE BIOMETRÍA CANCELABLE",
            size=24,
            weight=ft.FontWeight.BOLD
        ),
        ft.Text("Universidad de Cundinamarca", size=16),
        ft.Divider(),
        ft.Text("1. Registro e identificación", size=18),
        nombre,
        contrasena,
        ft.Row(
            controls=[
                ft.Button("Registrar usuario", on_click=registrar),
                ft.Button("Autenticar con huella", on_click=autenticar)
            ],
            wrap=True
        ),
        ft.Row(
            controls=[
                ft.Button("Revocar credencial", on_click=revocar),
                ft.Button("Limpiar", on_click=limpiar)
            ],
            wrap=True
        ),
        ft.Divider(),
        ft.Text("2. Renovación de credencial", size=18),
        nueva_contrasena,
        ft.Button(
            "Renovar credencial y contraseña",
            on_click=renovar
        ),
        ft.Divider(),
        ft.Text("3. Resultado de la operación", size=18),
        estado,
        ft.Divider(),
        ft.Text("4. Usuarios registrados", size=18),
        total,
        lista,
        ft.Divider(),
        ft.Text("5. Seguridad y base de datos", size=20,
                weight=ft.FontWeight.BOLD),
        ft.Text(
            "Escribe el usuario arriba. Para probar el descifrado, "
            "escribe también su contraseña actual."
        ),
        ft.Row(
            controls=[
                ft.Button(
                    "Consultar seguridad",
                    on_click=consultar_seguridad
                ),
                ft.Button(
                    "Probar cifrado",
                    on_click=probar_cifrado
                )
            ],
            wrap=True
        ),
        evidencias
    )

    actualizar_lista()


ft.run(main)
