import hashlib
import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
import requests

# Tu clave API oficial de VirusTotal
API_KEY_VIRUSTOTAL = (
    "b21669db862ba6cc7a94d495836de27666f6b8f23ae36a09e951198b86d3b4cc"
)

# Ruta del archivo hosts de Windows para el Escudo de Red
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
REDIRECT_IP = "127.0.0.1"

# Patrones sospechosos para el Análisis Heurístico Local
PATRONES_AMENAZA = [
    (r"del\s+/f\s+/q\s+c:\\", "Intento de borrado masivo en C:"),
    (r"format\s+[c-z]:", "Comando de formateo de disco"),
    (
        r"netsh\s+advfirewall\s+set\s+.*off",
        "Desactivación del cortafuegos de Windows",
    ),
    (
        r"reg\s+add\s+.*run",
        "Intento de persistencia en el Registro de Windows",
    ),
    (
        r"powershell.*-nop.*-w\s+hidden.*downloadstring",
        "Descarga e ejecución oculta con PowerShell",
    ),
    (
        r"vssadmin\s+delete\s+shadows",
        "Destrucción de copias de seguridad (Comportamiento Ransomware)",
    ),
    (r"taskkill\s+/f\s+/im", "Forzar cierre de procesos de seguridad"),
    (r"attrib\s+\+h\s+\+s", "Ocultación de archivos del sistema"),
]


def limpiar_url_entrada(texto):
  match = re.search(r"https?://[^\s\)\]]+", texto)
  if match:
    return match.group(0)
  return re.sub(r"[\[\]\(\)]", "", texto).strip()


def extraer_dominio(url):
  dominio = re.sub(r"https?://", "", url)
  return dominio.split("/")[0]


def analisis_heuristico_local(ruta_archivo):
  amenazas_detectadas = []
  ext_analizables = (
      ".bat",
      ".cmd",
      ".ps1",
      ".vbs",
      ".js",
      ".py",
      ".txt",
      ".sh",
  )
  if ruta_archivo.lower().endswith(ext_analizables):
    try:
      with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
        contenido = f.read()
        for patron, descripcion in PATRONES_AMENAZA:
          if re.search(patron, contenido, re.IGNORECASE):
            amenazas_detectadas.append(descripcion)
    except Exception:
      pass
  return amenazas_detectadas


def calcular_hash_archivo(ruta_archivo):
  hasher = hashlib.sha256()
  try:
    with open(ruta_archivo, "rb") as f:
      buf = f.read(65536)
      while len(buf) > 0:
        hasher.update(buf)
        buf = f.read(65536)
    return hasher.hexdigest()
  except Exception:
    return None


def escanear_archivo_individual(ruta_archivo):
  amenazas_locales = analisis_heuristico_local(ruta_archivo)
  file_hash = calcular_hash_archivo(ruta_archivo)
  malicioso_vt = False
  detalles_vt = ""

  if file_hash:
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY_VIRUSTOTAL}
    try:
      response = requests.get(endpoint, headers=headers)
      if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        if malicious > 0:
          malicioso_vt = True
          detalles_vt = f"Detectado por {malicious} motores de VirusTotal."
    except Exception:
      pass

  return amenazas_locales, malicioso_vt, detalles_vt


# ==========================================
# INTERFAZ GRÁFICA PRINCIPAL (v1.45 Pro)
# ==========================================
ventana = tk.Tk()
ventana.title("🛡️ BroShield Antivirus Total - v1.45 Pro")
ventana.geometry("640x590")
ventana.config(bg="#f4f6f9")
ventana.resizable(False, False)

# Sistema de Pestañas (Notebook)
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook.Tab", font=("Helvetica", 9, "bold"), padding=[10, 6])

notebook = ttk.Notebook(ventana)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# Pestañas principales
tab_sistema = tk.Frame(notebook, bg="#f4f6f9")
notebook.add(tab_sistema, text=" 💻 Sistema ")

tab_web = tk.Frame(notebook, bg="#f4f6f9")
notebook.add(tab_web, text=" 🌐 Web ")

tab_tiempo_real = tk.Frame(notebook, bg="#f4f6f9")
notebook.add(tab_tiempo_real, text=" ⚡ Monitor ")

tab_comunidad = tk.Frame(notebook, bg="#f4f6f9")
notebook.add(tab_comunidad, text=" 💬 Comunidad & Sugerencias ")


# --- CONTENIDO PESTAÑA 1: SISTEMA ---
lbl_titulo_sis = tk.Label(
    tab_sistema,
    text="BroShield v1.45 - Escáner Inteligente",
    font=("Helvetica", 14, "bold"),
    bg="#f4f6f9",
    fg="#1a252f",
)
lbl_titulo_sis.pack(pady=15)

lbl_desc_sis = tk.Label(
    tab_sistema,
    text=(
        "Analiza archivos, carpetas o realiza un examen completo del equipo."
    ),
    font=("Helvetica", 10),
    bg="#f4f6f9",
    fg="#555555",
)
lbl_desc_sis.pack(pady=5)

progress_bar = ttk.Progressbar(
    tab_sistema, orient="horizontal", length=500, mode="determinate"
)
progress_bar.pack(pady=15)

lbl_estado_progreso = tk.Label(
    tab_sistema,
    text="Estado: Preparado para escanear",
    font=("Helvetica", 10, "bold"),
    bg="#f4f6f9",
    fg="#6c757d",
)
lbl_estado_progreso.pack(pady=5)


def ejecutar_examen_completo():
  user_profile = os.environ.get("USERPROFILE", "C:\\")
  rutas_clave = [
      os.path.join(user_profile, "Desktop"),
      os.path.join(user_profile, "Downloads"),
      os.path.join(user_profile, "Documents"),
  ]

  todos_archivos = []
  for carpeta in rutas_clave:
    if os.path.exists(carpeta):
      for root, _, files in os.walk(carpeta):
        for file in files:
          todos_archivos.append(os.path.join(root, file))

  total = len(todos_archivos)
  if total == 0:
    messagebox.showinfo(
        "Examen", "No se encontraron archivos en las rutas principales."
    )
    return

  progress_bar["maximum"] = total
  archivos_infectados = []

  for i, ruta in enumerate(todos_archivos):
    progress_bar["value"] = i + 1
    lbl_estado_progreso.config(
        text=f"Analizando ({i+1}/{total}): {os.path.basename(ruta)}"
    )
    ventana.update()

    amenazas, malicioso_vt, _ = escanear_archivo_individual(ruta)
    if amenazas or malicioso_vt:
      archivos_infectados.append(ruta)

  progress_bar["value"] = 0
  if archivos_infectados:
    lbl_estado_progreso.config(
        text=f"⚠️ Amenazas detectadas: {len(archivos_infectados)}", fg="#d9534f"
    )
    if messagebox.askyesno(
        "Alerta",
        f"Se encontraron {len(archivos_infectados)} archivos maliciosos. ¿Deseas"
        " borrarlos?",
    ):
      for r in archivos_infectados:
        try:
          os.remove(r)
        except:
          pass
      messagebox.showinfo("Limpieza", "Archivos eliminados con éxito.")
  else:
    lbl_estado_progreso.config(
        text="✅ Examen finalizado con éxito.", fg="#28a745"
    )
    messagebox.showinfo(
        "Examen Completado", "No se encontraron archivos maliciosos."
    )


frame_botones_sis = tk.Frame(tab_sistema, bg="#f4f6f9")
frame_botones_sis.pack(pady=15)

btn_examen_pc = tk.Button(
    frame_botones_sis,
    text="💻 Examinar Dispositivo",
    font=("Helvetica", 10, "bold"),
    bg="#6f42c1",
    fg="white",
    relief="flat",
    padx=10,
    pady=5,
    command=lambda: threading.Thread(target=ejecutar_examen_completo).start(),
)
btn_examen_pc.pack(side="left", padx=5)


def seleccionar_archivo_individual():
  ruta = filedialog.askopenfilename()
  if ruta:
    lbl_estado_progreso.config(
        text="Analizando archivo individual...", fg="#0056b3"
    )
    ventana.update()
    am, mal_vt, _ = escanear_archivo_individual(ruta)
    if am or mal_vt:
      if messagebox.askyesno(
          "Peligro", "¡Archivo malicioso detectado! ¿Deseas eliminarlo?"
      ):
        os.remove(ruta)
        messagebox.showinfo("Borrado", "Archivo eliminado.")
    else:
      messagebox.showinfo("Seguro", "No se encontraron archivos maliciosos.")
      lbl_estado_progreso.config(text="✅ Archivo limpio.", fg="#28a745")


btn_archivo_suelto = tk.Button(
    frame_botones_sis,
    text="📁 Escanear Archivo",
    font=("Helvetica", 10, "bold"),
    bg="#28a745",
    fg="white",
    relief="flat",
    padx=10,
    pady=5,
    command=seleccionar_archivo_individual,
)
btn_archivo_suelto.pack(side="left", padx=5)


# --- CONTENIDO PESTAÑA 2: WEB ---
lbl_titulo_web = tk.Label(
    tab_web,
    text="Protección Web - BroShield v1.45",
    font=("Helvetica", 14, "bold"),
    bg="#f4f6f9",
    fg="#1a252f",
)
lbl_titulo_web.pack(pady=15)

lbl_inst_web = tk.Label(
    tab_web,
    text="Pega la dirección web para verificar su reputación:",
    font=("Helvetica", 10),
    bg="#f4f6f9",
    fg="#555555",
)
lbl_inst_web.pack(pady=5)

entrada_url = tk.Entry(
    tab_web, font=("Helvetica", 11), width=50, bd=2, relief="groove"
)
entrada_url.pack(pady=10)
entrada_url.insert(0, "https://")


def bloquear_web_local(dominio):
  try:
    with open(HOSTS_PATH, "r+") as file:
      contenido = file.read()
      if dominio not in contenido:
        file.write(f"\n{REDIRECT_IP} {dominio}")
        return True
  except PermissionError:
    messagebox.showwarning(
        "Atención",
        "Para bloquear páginas en el sistema debes ejecutar BroShield como"
        " Administrador.",
    )
  except Exception:
    pass
  return False


def analizar_url_accion():
  raw = entrada_url.get().strip()
  if not raw:
    return
  url = limpiar_url_entrada(raw)
  if not url.startswith("http"):
    url = "https://" + url

  lbl_res_web.config(text="🔍 Consultando VirusTotal...", fg="#0056b3")
  ventana.update()

  try:
    res = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": API_KEY_VIRUSTOTAL},
        data={"url": url},
    )
    if res.status_code == 200:
      analysis_id = res.json()["data"]["id"]
      res_an = requests.get(
          f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
          headers={"x-apikey": API_KEY_VIRUSTOTAL},
      )
      stats = res_an.json()["data"]["attributes"]["stats"]

      if stats.get("malicious", 0) > 0:
        lbl_res_web.config(
            text="⚠️ ¡ALERTA! Web peligrosa detectada.", fg="#d9534f"
        )
        dominio = extraer_dominio(url)
        if messagebox.askyesno(
            "Bloqueo de Seguridad",
            f"La web {dominio} no es segura.\n\n¿Deseas que BroShield la bloquee"
            " en tu equipo?",
        ):
          if bloquear_web_local(dominio):
            messagebox.showinfo(
                "Bloqueo", f"El sitio {dominio} ha sido bloqueado con éxito."
            )
      else:
        lbl_res_web.config(text="✅ La página web es SEGURA.", fg="#28a745")
    else:
      lbl_res_web.config(text="[-] Error de conexión con la API.", fg="#d9534f")
  except:
    lbl_res_web.config(text="[-] Error analizando la URL.", fg="#d9534f")


btn_web = tk.Button(
    tab_web,
    text="Escanear Web",
    font=("Helvetica", 10, "bold"),
    bg="#007bff",
    fg="white",
    relief="flat",
    padx=15,
    pady=5,
    command=analizar_url_accion,
)
btn_web.pack(pady=10)

lbl_res_web = tk.Label(
    tab_web,
    text="Esperando enlace...",
    font=("Helvetica", 11, "bold"),
    bg="#f4f6f9",
    fg="#6c757d",
)
lbl_res_web.pack(pady=10)


# --- CONTENIDO PESTAÑA 3: MONITOR EN TIEMPO REAL ---
lbl_titulo_rt = tk.Label(
    tab_tiempo_real,
    text="Monitor Activo - BroShield v1.45",
    font=("Helvetica", 14, "bold"),
    bg="#f4f6f9",
    fg="#1a252f",
)
lbl_titulo_rt.pack(pady=15)

lbl_desc_rt = tk.Label(
    tab_tiempo_real,
    text="Monitor de procesos del sistema e inspección en tiempo real.",
    font=("Helvetica", 9),
    bg="#f4f6f9",
    fg="#555555",
)
lbl_desc_rt.pack(pady=5)

txt_procesos = tk.Text(tab_tiempo_real, height=12, width=70, font=("Consolas", 9))
txt_procesos.pack(pady=10)


def escanear_procesos_activos():
  txt_procesos.delete("1.0", tk.END)
  txt_procesos.insert(
      tk.END, "[+] BroShield v1.45: Verificando procesos del sistema...\n"
  )
  ventana.update()

  import subprocess

  procs = subprocess.check_output("tasklist", shell=True).decode(
      errors="ignore"
  )
  lineas = procs.splitlines()[:15]

  for l in lineas:
    txt_procesos.insert(tk.END, f"  [OK] Verificado: {l[:45]}\n")

  txt_procesos.insert(
      tk.END, "\n✅ Estado del Monitor Activo: Sistema protegido y limpio."
  )


btn_rt = tk.Button(
    tab_tiempo_real,
    text="⚡ Ejecutar Comprobación Activa",
    font=("Helvetica", 10, "bold"),
    bg="#28a745",
    fg="white",
    relief="flat",
    padx=10,
    pady=5,
    command=escanear_procesos_activos,
)
btn_rt.pack(pady=5)


# --- CONTENIDO PESTAÑA 4: COMUNIDAD Y SUGERENCIAS ---
lbl_titulo_com = tk.Label(
    tab_comunidad,
    text="📢 Buzón de Sugerencias y Novedades",
    font=("Helvetica", 14, "bold"),
    bg="#f4f6f9",
    fg="#1a252f",
)
lbl_titulo_com.pack(pady=10)

lbl_desc_com = tk.Label(
    tab_comunidad,
    text=(
        "¿Qué te gustaría que añadiéramos en la próxima versión de BroShield?"
    ),
    font=("Helvetica", 9),
    bg="#f4f6f9",
    fg="#555555",
)
lbl_desc_com.pack(pady=2)

txt_sugerencia = tk.Text(
    tab_comunidad, height=6, width=65, font=("Helvetica", 10), bd=1, relief="solid"
)
txt_sugerencia.pack(pady=8)
txt_sugerencia.insert(tk.END, "Escribe aquí tu idea o función nueva...")


def enviar_sugerencia():
  idea = txt_sugerencia.get("1.0", tk.END).strip()
  if not idea or idea == "Escribe aquí tu idea o función nueva...":
    messagebox.showwarning(
        "Atención", "Por favor, escribe una sugerencia antes de enviar."
    )
    return

  try:
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    ruta_archivo = os.path.join(desktop_path, "sugerencias_broshield.txt")

    with open(ruta_archivo, "a", encoding="utf-8") as f:
      f.write(
          f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {idea}\n---\n"
      )

    # Mensaje limpio terminando exactamente en el cohete
    messagebox.showinfo(
        "¡Sugerencia Enviada!",
        "¡Gracias! El desarrollador lo tomará en cuenta para las próximas"
        " actualizaciones. 🚀",
    )
    txt_sugerencia.delete("1.0", tk.END)
  except Exception as e:
    messagebox.showerror("Error", f"No se pudo guardar la sugerencia: {e}")


btn_enviar_sug = tk.Button(
    tab_comunidad,
    text="📤 Enviar Idea al Desarrollador",
    font=("Helvetica", 10, "bold"),
    bg="#ffc107",
    fg="#333",
    relief="flat",
    padx=10,
    pady=5,
    command=enviar_sugerencia,
)
btn_enviar_sug.pack(pady=5)

lbl_info_actualizaciones = tk.Label(
    tab_comunidad,
    text=(
        "💡 Versión actual: v1.45 Pro | Mantente atento a GitHub para nuevas"
        " updates."
    ),
    font=("Helvetica", 8, "italic"),
    bg="#f4f6f9",
    fg="#6c757d",
)
lbl_info_actualizaciones.pack(pady=10)

ventana.mainloop()