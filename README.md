# Log Forensics for Autopsy

*   [Modules](#modules)
*   [Installation](#windows-installation)
*   [Authors + Help](#authors)
*   [Project Description](#project-description-pt)

# Modules

**LFA** was tested using Autopsy 4.6.0 in two different personal computers, both running Windows 10. It should also run in Linux.

**findLogFilesGUI:** A file ingest module that finds log files and saves them as artifacts (.evtx, .log, .dmp, .wer, .etl). In case of .wer file it creates a Reported program artifact if the .wer is valid. In case of .log file it creates an artifact for each different IP found in the .log, the number of occurences in that file, the IP type, the domain, and protocols found in the same line as the IP. If the user specified any RegEx, they will also be looked up by LFA and saved as artifacts (occurrences and content matched). This module also searches for Windows startup information in certain .xml log files.

**reportWer:** A report module that queries the blackboard for the information that the file ingest produced and reports it to HTML, Excel, and/or DFXML. The Excel format contains several charts for statistics. The report module is used to enhance the information gathered by the file ingest module.

# Windows installation

1.  Download as ZIP directly from here or from [Zenodo](https://zenodo.org/record/1340750) (if you choose Zenodo, pick the latest version)
2.  Go to your Python Modules folder:
    1. Open Autopsy
    2. Tools > Python Plugins
3.  Unzip the downloaded ZIP inside the folder opened by Autopsy
4.  Restart or start Autopsy to compile all the libraries and files
5.  Open your case and run the LFA file ingest module
6.  Run the LFA Report Module with the desired options
7.  Open the default report (HTML) or go to Reports in the Tree Viewer to choose a report to open

# Authors

LFA was developed by Luís Andrade and João Silva, two Computer Engineering graduates.
Mentored by Patrício Domingues and Miguel Frade and proposed by Patrício Domingues.

If you have any suggestion or find any bug, please contact us or create an issue in this repository.

**Contacts:**  
Luís Andrade - 2180234@my.ipleiria.pt
João Silva - 2180073@my.ipleiria.pt  

# Project description (PT)

Área Temática: DA (Desenvolvimento de Aplicações)

Descrição:

A aplicação Autopsy (https://www.sleuthkit.org/autopsy/) é uma aplicação disponível sob licença de código aberto, para a realização de perícias informáticas forenses. Na prática, o Autopsy agrega sobre uma mesma interface várias funcionalidades, nomeadamente as disponibilizadas pelo Sleuthkit (https://www.sleuthkit.org/). A elevada dinâmica do projeto, a sua extensibilidade através de módulos (JAVA ou Python), e ainda o acesso gratuito ao software fazem do Autopsy uma aplicação de referência no domínio das perícias de informática forense. Com o projeto Log Forensics for Autopsy (LFA) pretende-se o desenvolvimento de um módulo para o Autopsy que possibilite a deteção e validação de registos do sistema (log) e em particulares dos logs produzidos pelo sistema operativo Windows e aplicações em situações especiais, nomeadamente quando ocorre terminações abruptas. Exemplos desses logs são os existentes nos diretórios C:\ProgramData\Microsoft\Windows\WER, C:\Users\UTILIZADOR\AppData\Local\Microsoft\Windows\WER (em que UTILIZADOR corresponde a um login do sistema), C:\windows\LiveKernelReports e C:\windows\logs. O objetivo principal do projeto LFA é a criação de um módulo para Autopsy que seja capaz de extrair informação com valor forense dos logs acima indicados, bem como de outros similares. O módulo LFA deve estar preparado para análise ao sistemas operativos Windows 7, Windows 8 e Windows 10.
