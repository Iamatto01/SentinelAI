import base64
import zlib
import urllib.request
import sys

def generate_diagram(plantuml_text, output_file):
    # Kroki supports many diagram types, including plantuml
    # We can just POST the raw text to https://kroki.io/plantuml/png
    
    url = "https://kroki.io/plantuml/png"
    req = urllib.request.Request(url, data=plantuml_text.encode('utf-8'), method='POST')
    req.add_header('Content-Type', 'text/plain')
    
    try:
        with urllib.request.urlopen(req) as response:
            with open(output_file, 'wb') as f:
                f.write(response.read())
        print(f"Successfully generated diagram at {output_file}")
    except Exception as e:
        print(f"Error generating diagram: {e}")

plantuml_code = """@startuml
left to right direction
skinparam packageStyle rectangle
skinparam shadowing false

skinparam usecase {
  BackgroundColor #E0E0E0
  BorderColor #808080
}
skinparam actor {
  BackgroundColor white
  BorderColor black
}
skinparam rectangle {
  BackgroundColor #F5F5F5
  BorderColor #808080
}

actor "Administrator / Analyst" as Admin
actor "SentinelAI System\\(Backend)" as Backend
actor "Client" as Client
actor "GROQ (API)" as GROQ

rectangle "SentinelAI System" {
  usecase "Sign In / Role Assignment" as UC1
  usecase "Authentication" as UC2
  usecase "Review Vulnerabilities" as UC3
  usecase "Interact with AI Chat" as UC4
  usecase "Manage Projects & Target Scope" as UC5
  usecase "Launch & Monitor Scans" as UC6
  usecase "Generate PDF Assessment Report" as UC7
}

Admin --> UC1
Admin --> UC3
Admin --> UC5

Backend --> UC2 : Verify
Backend --> UC6
Backend --> UC7

Client --> UC1
Client --> UC3
Client --> UC7

GROQ --> UC4

UC1 ..> UC2 : <<include>>
UC3 <.. UC4 : <<extend>>
UC5 <.. UC6 : <<extend>>
UC5 <.. UC7 : <<extend>>

@enduml
"""

generate_diagram(plantuml_code, "use_case_diagram.png")
