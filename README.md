# microsoft-purview-dlp-risk-scenarios
Mise en pratique de Microsoft Purview (DLP, MIP, Audit) à travers des scénarios de fuite de données, dans un contexte SOC, dans le cadre d’un stage en Infrastructure &amp; Sécurité.

# Microsoft Purview – Analyse de risques et protection contre la fuite de données

## Contexte
Ce projet s’inscrit dans le cadre de mon **stage en Infrastructure & Sécurité**, avec un focus SOC, au sein d’un environnement **Microsoft 365**.

L’objectif principal est de **monter en compétence sur Microsoft Purview** à travers des cas pratiques, en simulant des **scénarios réels de fuite de données en entreprise** et en mettant en place des mesures de détection, de blocage et de protection.

---

## Objectifs du projet
- Comprendre et utiliser **Microsoft Purview** dans un contexte SOC
- Identifier des **scénarios de fuite de données réalistes**
- Évaluer le risque (Probabilité × Impact)
- Mettre en place des **mesures de remédiation** pour réduire le risque à 0
- Apprendre à **investiguer les incidents** via Microsoft Purview Audit

---

## Environnement de travail
- Environnement **Microsoft 365 de test**
- Comptes utilisateurs simulant un usage réel
- Outils principaux utilisés :
  - Microsoft Purview
  - Data Loss Prevention (DLP)
  - Microsoft Information Protection (MIP)
  - Sensitivity Labels & Auto‑labeling
  - Microsoft Purview Audit
  - Endpoint DLP

---

## Contenu du projet

### Analyse des risques (Excel)
Un fichier Excel contenant **13 scénarios de risques de fuite de données**, par exemple :
- Téléchargement de fichiers sensibles
- Partage non autorisé (interne / externe)
- Email non chiffré
- Copie vers clé USB
- Copy / Paste vers applications non sécurisées
- Capture d’écran et impression de documents sensibles
- Shadow IT et contournement via archives ZIP

Pour chaque scénario :
- Évaluation du risque initial (Probabilité × Impact)
- Définition des outils de sécurité adaptés
- Mise en place de règles DLP et MIP
- Réévaluation du risque après remédiation (objectif : 0)

---

### 📄 Documentation (PDF)
Une documentation expliquant :
- La démarche globale
- Les choix techniques effectués
- L’utilisation de Microsoft Purview
- Le fonctionnement de DLP et MIP
- Les Sensitive Information Types (SIT)
- Les techniques de détection :
  - Reconnaissance de format
  - Algorithme de Luhn
  - Analyse contextuelle
  - OCR
  - Machine Learning
- L’utilisation de Microsoft Purview Audit pour l’investigation

---

## Approche SOC
Le projet est abordé avec une **logique SOC**, incluant :
- Détection des incidents
- Alertes administrateur
- Blocage automatique des actions à risque
- Prévention côté utilisateur (policy tips)
- Investigation post‑incident via Audit
- Analyse de la source de la fuite (par emplacement)

---

## État du projet
**Projet en cours**

Ce projet correspond à un **état d’avancement** de mon stage.  
Il est amené à évoluer avec :
- De nouveaux scénarios de risques
- Une amélioration des règles existantes
- Une approche plus poussée de l’investigation et du reporting SOC

---

## Compétences mises en œuvre
- Microsoft Purview
- Data Loss Prevention (DLP)
- Microsoft Information Protection (MIP)
- Protection des données
- Sécurité Endpoint
- Analyse de risques
- Investigation SOC
- Audit et analyse de logs
- Documentation technique

---

## Auteur
**Yacine BEN OMRANE**  
Stagiaire – Infrastructure & Sécurité  
Projet réalisé dans le cadre d’un stage SOC – Microsoft Purview
