"""
Herramienta OSINT para Verificación de Cuentas en Redes Sociales
Autor: Sistema de Pruebas OSINT
Versión: DEDSEC001
"""

import requests
import json
import time
import re
import csv
from datetime import datetime
from urllib.parse import quote
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Optional
import hashlib
import base64

@dataclass
class SocialAccount:
    platform: str
    username: str
    url: str
    exists: bool
    profile_data: Dict
    confidence_score: float
    last_checked: str

@dataclass
class PersonProfile:
    name: str
    email: str
    phone: str
    location: str
    profession: str
    common_username: str
    website: str

class OSINTSocialVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.platforms = {
            'twitter': 'https://twitter.com/{}',
            'instagram': 'https://www.instagram.com/{}',
            'facebook': 'https://www.facebook.com/{}',
            'linkedin': 'https://www.linkedin.com/in/{}',
            'github': 'https://github.com/{}',
            'pinterest': 'https://www.pinterest.com/{}',
            'tiktok': 'https://www.tiktok.com/@{}',
            'behance': 'https://www.behance.net/{}',
            'dribbble': 'https://dribbble.com/{}',
            'medium': 'https://medium.com/@{}',
            'youtube': 'https://www.youtube.com/user/{}',
            'reddit': 'https://www.reddit.com/user/{}',
            'telegram': 'https://t.me/{}',
            'twitch': 'https://www.twitch.tv/{}',
            'snapchat': 'https://www.snapchat.com/add/{}'
        }
        self.results = []
        self.report_data = {
            'timestamp': datetime.now().isoformat(),
            'target_profile': None,
            'found_accounts': [],
            'verification_summary': {},
            'recommendations': []
        }

    def log_error(self, message: str):
        with open("osint_errors.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} - {message}\n")

    def set_target_profile(self, profile: PersonProfile):
        self.report_data['target_profile'] = {
            'name': profile.name,
            'email': profile.email,
            'phone': profile.phone,
            'location': profile.location,
            'profession': profile.profession,
            'common_username': profile.common_username,
            'website': profile.website
        }
        print(f"[INFO] Perfil objetivo establecido: {profile.name}")

    def check_username_availability(self, username: str, platform: str) -> SocialAccount:
        url = self.platforms[platform].format(username)
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            exists = self._analyze_response(response, platform)
            profile_data = {}
            confidence_score = 0.0
            if exists:
                profile_data = self._extract_profile_data(response, platform)
                confidence_score = self._calculate_confidence_score(profile_data, platform)
            return SocialAccount(
                platform=platform,
                username=username,
                url=url,
                exists=exists,
                profile_data=profile_data,
                confidence_score=confidence_score,
                last_checked=datetime.now().isoformat()
            )
        except requests.RequestException as e:
            error_msg = f"Error al verificar {platform}: {e}"
            print(f"[ERROR] {error_msg}")
            self.log_error(error_msg)
            return SocialAccount(
                platform=platform,
                username=username,
                url=url,
                exists=False,
                profile_data={},
                confidence_score=0.0,
                last_checked=datetime.now().isoformat()
            )

    def search_all_platforms(self, username: str) -> List[SocialAccount]:
        print(f"[INFO] Buscando usuario: {username}")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_platform = {executor.submit(self.check_username_availability, username, platform): platform for platform in self.platforms}
            for future in concurrent.futures.as_completed(future_to_platform):
                account = future.result()
                if account.exists:
                    print(f"[FOUND] {account.platform}: {account.url}")
                    results.append(account)
                    self.report_data['found_accounts'].append({
                        'platform': account.platform,
                        'username': username,
                        'url': account.url,
                        'confidence_score': account.confidence_score,
                        'profile_data': account.profile_data
                    })
        return results

    def _analyze_response(self, response: requests.Response, platform: str) -> bool:
        if response.status_code == 200:
            content = response.text.lower()
            not_found_patterns = {
                'twitter': ["this account doesn't exist", "account suspended", "profile not found"],
                'instagram': ["page not found", "user not found", "sorry, this page isn't available"],
                'facebook': ["page not found", "content not found", "profile not available"],
                'linkedin': ["page not found", "member not found", "profile not found"],
                'github': ["not found", "404", "doesn't exist"],
                'pinterest': ["page not found", "profile not found"],
                'tiktok': ["couldn't find this account", "no content found"],
                'behance': ["page not found", "profile not found"],
                'dribbble': ["page not found", "profile not found"],
                'medium': ["page not found", "profile not found"],
                'youtube': ["channel doesn't exist", "404", "user not found"],
                'reddit': ["page not found", "user not found"],
                'telegram': ["username not found", "user not found"],
                'twitch': ["page not found", "user not found"],
                'snapchat': ["page not found", "user not found"]
            }
            if platform in not_found_patterns:
                for pattern in not_found_patterns[platform]:
                    if pattern in content:
                        return False
            return True
        return False

    def _extract_profile_data(self, response: requests.Response, platform: str) -> Dict:
        content = response.text
        profile_data = {}
        patterns = {
            'name': [
                r'<title>([^<]+)</title>',
                r'"name":\s*"([^"]+)"',
                r'<meta property="og:title" content="([^"]+)"'
            ],
            'description': [
                r'<meta name="description" content="([^"]+)"',
                r'<meta property="og:description" content="([^"]+)"',
                r'"description":\s*"([^"]+)"'
            ],
            'followers': [
                r'(\d+(?:,\d+)*)\s*followers',
                r'"followers":\s*(\d+)',
                r'(\d+(?:\.\d+)?[KM]?)\s*followers'
            ],
            'location': [
                r'"location":\s*"([^"]+)"',
                r'<meta property="og:locale" content="([^"]+)"'
            ]
        }
        for field, regex_list in patterns.items():
            for pattern in regex_list:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    profile_data[field] = match.group(1)
                    break
        if platform == 'linkedin':
            job_pattern = r'"headline":\s*"([^"]+)"'
            job_match = re.search(job_pattern, content)
            if job_match:
                profile_data['job_title'] = job_match.group(1)
        elif platform == 'github':
            repo_pattern = r'"public_repos":\s*(\d+)'
            repo_match = re.search(repo_pattern, content)
            if repo_match:
                profile_data['public_repos'] = repo_match.group(1)
        return profile_data

    def _calculate_confidence_score(self, profile_data: Dict, platform: str) -> float:
        score = 0.0
        score += 0.3
        if profile_data.get('name'):
            score += 0.2
        if profile_data.get('description'):
            score += 0.2
        if profile_data.get('followers'):
            score += 0.1
        if profile_data.get('location'):
            score += 0.1
        platform_bonus = {
            'linkedin': 0.1,  
            'github': 0.1,   
            'behance': 0.1,  
            'dribbble': 0.1  
        }
        if platform in platform_bonus:
            score += platform_bonus[platform]
        return min(score, 1.0)

    def search_email_presence(self, email: str) -> Dict:
        print(f"[INFO] Buscando email: {email}")
        results = {
            'email': email,
            'found_in_breaches': False,
            'public_presence': [],
            'verification_status': 'unknown'
        }
        google_query = f'"{email}"'
        print(f"[INFO] Consulta de Google sugerida: {google_query}")
        results['verification_status'] = 'requires_manual_check'
        return results

    def search_phone_presence(self, phone: str) -> Dict:
        print(f"[INFO] Buscando teléfono: {phone}")
        results = {
            'phone': phone,
            'whatsapp_business': False,
            'telegram_found': False,
            'public_listings': []
        }
        if re.match(r'^\+\d{1,3}\s?\d{3}\s?\d{3}\s?\d{3}$', phone):
            results['format_valid'] = True
        else:
            results['format_valid'] = False
        return results

    def generate_username_variants(self, base_username: str) -> List[str]:
        variants = [base_username]
        variants.extend([
            base_username + '1',
            base_username + '2',
            base_username + '_',
            base_username + '.',
            base_username + '-',
            base_username + '123',
            base_username.replace('_', ''),
            base_username.replace('_', '.'),
            base_username.replace('_', '-'),
        ])
        return list(set(variants))

    def comprehensive_search(self, profile: PersonProfile) -> Dict:
        print(f"[INFO] Iniciando búsqueda comprensiva para: {profile.name}")
        self.set_target_profile(profile)
        main_results = self.search_all_platforms(profile.common_username)
        variants = self.generate_username_variants(profile.common_username)
        variant_results = []
        for variant in variants[:5]:
            if variant != profile.common_username:
                print(f"[INFO] Probando variante: {variant}")
                variant_results.extend(self.search_all_platforms(variant))
        email_results = self.search_email_presence(profile.email)
        phone_results = self.search_phone_presence(profile.phone)
        self.report_data['verification_summary'] = {
            'main_username_results': len(main_results),
            'variant_results': len(variant_results),
            'email_verification': email_results,
            'phone_verification': phone_results,
            'total_accounts_found': len(main_results) + len(variant_results),
            'high_confidence_accounts': len([r for r in main_results + variant_results if r.confidence_score > 0.7])
        }
        self._generate_recommendations()
        return self.report_data

    def _generate_recommendations(self):
        recommendations = []
        total_accounts = self.report_data['verification_summary']['total_accounts_found']
        if total_accounts > 10:
            recommendations.append("Alto número de cuentas encontradas - considerar auditar perfiles no utilizados")
        if total_accounts > 5:
            recommendations.append("Implementar autenticación de dos factores en todas las cuentas")
        recommendations.extend([
            "Verificar configuraciones de privacidad en todas las plataformas",
            "Usar nombres de usuario únicos para diferentes propósitos",
            "Monitorear regularmente la presencia en línea",
            "Considerar el uso de un gestor de contraseñas"
        ])
        self.report_data['recommendations'] = recommendations

    def export_results_csv(self, filename: str = None):
        if not filename:
            filename = f"osint_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['platform', 'username', 'url', 'exists', 'confidence_score', 'profile_data']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for account in self.report_data['found_accounts']:
                writer.writerow({
                    'platform': account['platform'],
                    'username': account['username'],
                    'url': account['url'],
                    'exists': True,
                    'confidence_score': account['confidence_score'],
                    'profile_data': json.dumps(account['profile_data'])
                })
        print(f"[INFO] Resultados exportados a: {filename}")

    def export_results_json(self, filename: str = None):
        if not filename:
            filename = f"osint_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.report_data, jsonfile, indent=2, ensure_ascii=False)
        print(f"[INFO] Reporte completo exportado a: {filename}")

    def export_results_txt(self, filename: str = None):
        if not filename:
            filename = f"osint_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            for account in self.report_data['found_accounts']:
                f.write(f"{account['platform']}: {account['url']} (Confianza: {account['confidence_score']})\n")
        print(f"[INFO] Resultados exportados a: {filename}")

    def print_summary(self):
        print("="*60)
        print("RESUMEN DE VERIFICACIÓN OSINT")
        print("="*60)
        if self.report_data['target_profile']:
            profile = self.report_data['target_profile']
            print(f"Objetivo: {profile['name']}")
            print(f"Email: {profile['email']}")
            print(f"Usuario principal: {profile['common_username']}")
            print(f"Ubicación: {profile['location']}")
            print(f"Profesión: {profile['profession']}")
        print(f"\nCuentas encontradas: {len(self.report_data['found_accounts'])}")
        print(f"Plataformas con presencia:")
        for account in self.report_data['found_accounts']:
            confidence = account['confidence_score']
            status = "ALTA" if confidence > 0.7 else "MEDIA" if confidence > 0.4 else "BAJA"
            print(f"  - {account['platform']}: {account['url']} (Confianza: {status})")
        print(f"\nRecomendaciones de seguridad:")
        for i, rec in enumerate(self.report_data['recommendations'], 1):
            print(f"  {i}. {rec}")
        print("="*60)

    def validate_email(self, email: str) -> bool:
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    def validate_phone(self, phone: str) -> bool:
        return bool(re.match(r'^\+?\d[\d\s-]{7,}$', phone))


def get_user_input():
    print("Ingresa los datos de la persona a investigar:")
    print("(Presiona Enter para omitir campos opcionales)")
    print("-" * 50)
    name = input("Nombre completo: ").strip()
    if not name:
        print(" El nombre es obligatorio")
        return None
    email = input("Email (opcional): ").strip()
    if email and not OSINTSocialVerifier().validate_email(email):
        print(" Email parece inválido")
    phone = input("Teléfono (opcional): ").strip()
    if phone and not OSINTSocialVerifier().validate_phone(phone):
        print(" Teléfono parece inválido")
    location = input("Ubicación (opcional): ").strip()
    profession = input("Profesión (opcional): ").strip()
    common_username = input("Nombre de usuario principal: ").strip()
    if not common_username:
        print(" El nombre de usuario es obligatorio")
        return None
    website = input("Sitio web (opcional): ").strip()
    return PersonProfile(
        name=name,
        email=email,
        phone=phone,
        location=location,
        profession=profession,
        common_username=common_username,
        website=website
    )

def use_example_profile():
    return PersonProfile(
        name="María Elena Rodríguez",
        email="maria.rodriguez.design@gmail.com",
        phone="+34 600 123 456",
        location="Barcelona, España",
        profession="Diseñadora Gráfica",
        common_username="mariaelena_designs",
        website="www.mariaelena-portfolio.com"
    )

def main():
    print("Herramienta OSINT para Verificación de Redes Sociales")
    print("="*55)
    verifier = OSINTSocialVerifier()
    print("\nSelecciona una opción:")
    print("1. Ingresar datos manualmente")
    print("2. Usar perfil de ejemplo (María Elena Rodríguez)")
    print("3. Salir")
    choice = input("\nIngresa tu opción (1-3): ").strip()
    if choice == "1":
        profile = get_user_input()
        if profile is None:
            print(" Error: Datos incompletos. Saliendo...")
            return
    elif choice == "2":
        profile = use_example_profile()
        print(f"Usando perfil de ejemplo: {profile.name}")
    elif choice == "3":
        print("Saliendo del programa...")
        return
    else:
        print(" Opción inválida. Saliendo...")
        return
    print(f"\n RESUMEN DEL PERFIL A INVESTIGAR:")
    print(f"   Nombre: {profile.name}")
    print(f"   Email: {profile.email if profile.email else 'No proporcionado'}")
    print(f"   Teléfono: {profile.phone if profile.phone else 'No proporcionado'}")
    print(f"   Ubicación: {profile.location if profile.location else 'No proporcionado'}")
    print(f"   Profesión: {profile.profession if profile.profession else 'No proporcionado'}")
    print(f"   Usuario principal: {profile.common_username}")
    print(f"   Sitio web: {profile.website if profile.website else 'No proporcionado'}")
    confirm = input("\n¿Continuar con la búsqueda? (s/n): ").strip().lower()
    if confirm not in ['s', 'si', 'y', 'yes']:
        print("Búsqueda cancelada por el usuario")
        return
    print(f"\n Iniciando búsqueda OSINT para: {profile.name}")
    print(" Esto puede tomar varios minutos...")
    results = verifier.comprehensive_search(profile)
    verifier.print_summary()
    export_choice = input("\n¿Exportar resultados? (s/n): ").strip().lower()
    if export_choice in ['s', 'si', 'y', 'yes']:
        format_choice = input("¿Formato de exportación? (csv/json/txt): ").strip().lower()
        if format_choice == "csv":
            verifier.export_results_csv()
        elif format_choice == "json":
            verifier.export_results_json()
        elif format_choice == "txt":
            verifier.export_results_txt()
        else:
            print("Formato no reconocido, exportando por defecto en CSV.")
            verifier.export_results_csv()
        print(" Resultados exportados exitosamente")
    print("\n Búsqueda completada.")

if __name__ == "__main__":
    main()
