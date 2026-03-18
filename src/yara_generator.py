import os
import re

RULES_DIR = "rules"
os.makedirs(RULES_DIR, exist_ok=True)

RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def validate_rule_name(name):
    return RULE_NAME_RE.match(name) is not None

def validate_string(s):
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        hex_values = s[1:-1].strip().split()
        for h in hex_values:
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", h):
                print("Hex invalide")
                return False
    return True

def ask_list(prompt):
    val = input(prompt)
    return [v.strip() for v in val.split(",") if v.strip()]

def create_yara_rule(name, tags, description, strings, condition):
    rule = f"rule {name}\n{{\n"
    if tags:
        rule += f"    tags = [{', '.join(tags)}]\n"
    if description:
        rule += "    meta:\n"
        rule += f'        description = "{description}"\n'
    rule += "    strings:\n"
    for i, s in enumerate(strings):
        if s.startswith("{") and s.endswith("}"):
            rule += f"        $s{i} = {s}\n"
        else:
            rule += f'        $s{i} = "{s}"\n'
    rule += "    condition:\n"
    rule += f"        {condition}\n"
    rule += "}\n"
    return rule

def save_rule(rule_text, name):
    filename = os.path.join(RULES_DIR, f"{name}.yar")
    with open(filename, "w") as f:
        f.write(rule_text)
    return filename

def generate_rule():
    while True:
        name = input("\nNom:\nExemples: (Trojan_Win32_Agent,Ransomware_Lockbit,Backdoor_Python,TestRule) : ")
        if validate_rule_name(name):
            break
        print("Nom invalide")

    tags = ask_list("\nTags:\nExemples: (trojan,win32,malware,loader,ransomware,test,lab) : ")

    description = input("\nDescription:\nExemples: (Detecte CreateProcess,Detecte header PE,Detecte string ransom,Test rule) : ")

    while True:
        try:
            num_strings = int(input("\nNombre de chaînes:\nExemples: (1,2,3,4) : "))
            if num_strings > 0:
                break
        except:
            pass

    strings = []
    for i in range(num_strings):
        while True:
            s = input('\nChaîne:\nExemples: ("cmd.exe","CreateProcessA",{ 4D 5A },{ 6A 40 68 00 30 00 }) : ')
            if validate_string(s):
                strings.append(s)
                break

    condition = input("\nCondition:\nExemples: (all of them,any of them,uint16(0)==0x5A4D,all of them and filesize<1MB) : ")

    rule_text = create_yara_rule(name, tags, description, strings, condition)
    print("\n--- APERCU ---\n")
    print(rule_text)

    while True:
        confirm = input("Sauvegarder ? (o/n) : ").lower()
        if confirm in ["o", "n"]:
            break

    if confirm == "o":
        filename = save_rule(rule_text, name)
        print("\nOK")
        print("Règle :", name)
        print("Fichier :", filename)
        print("Dossier :", RULES_DIR)
        print("Votre règle est disponible dans le répertoire rules et prête à être déployée.")
    else:
        print("Annulé")

def main():
    print("YARA rule generator")
    while True:
        generate_rule()
        while True:
            again = input("\nNouvelle règle ? (o/n) : ").lower()
            if again in ["o", "n"]:
                break
        if again == "n":
            print("Fin")
            break

if __name__ == "__main__":
    main()