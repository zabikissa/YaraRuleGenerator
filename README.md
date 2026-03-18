# YaraRuleGenerator

Générateur interactif de règles YARA en Python.

==>Fonctionnalités

- Génération multiple de règles YARA
- Validation des noms et des chaînes hex
- Aperçu avant sauvegarde
- Sauvegarde automatique dans `rules/`
- Interface CLI simple et professionnelle

==>Installation

1. Cloner le repo :

```bash
git clone https://github.com/zabikissa/YaraRuleGenerator.git
cd YaraRuleGenerator


2. Installer Python 3.10+ (Windows)

3. Lancer le générateur :
   python src/yara_generator.py

==> Utilisation

1. Répondre aux questions : Nom, Tags, Description, Chaînes, Condition
2. Voir l’aperçu
3. Sauvegarder
4. La règle sera disponible dans rules/ et prête à être déployée





Exemple d'usage

Nom:
Exemples: (Trojan_Win32_Agent,Ransomware_Lockbit,Backdoor_Python,TestRule) : TestRule

Tags:
Exemples: (trojan,win32,malware,loader,ransomware,test,lab) : trojan,win32

Description:
Exemples: (Detecte CreateProcess,Detecte header PE,Detecte string ransom,Test rule) : test

Nombre de chaînes:
Exemples: (1,2,3,4) : 1

Chaîne:
Exemples: ("cmd.exe","CreateProcessA",{ 4D 5A },{ 6A 40 68 00 30 00 }) : "cmd.exe"

Condition:
Exemples: (all of them,any of them,uint16(0)==0x5A4D,all of them and filesize<1MB) : all of them

Licence : MIT