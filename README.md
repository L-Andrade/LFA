# LFA

Log Forensics for Autopsy

# Modules

findLogFilesGUI: A file ingest module that finds log files (.evtx, .log, .dmp, .wer, .etl). In case of .wer file it also creates a Reported program artifact if the .wer is valid.

reportWer: A report module that queries the blackboard for the information that the file ingest produced and reports it to HTML and Excel.

# Project description (PT)

Área Temática: DA (Desenvolvimento de Aplicações)

Descrição:

A aplicação Autopsy (https://www.sleuthkit.org/autopsy/) é uma aplicação disponível sob licença de código aberto, para a realização de perícias informáticas forenses. Na prática, o Autopsy agrega sobre uma mesma interface várias funcionalidades, nomeadamente as disponibilizadas pelo Sleuthkit (https://www.sleuthkit.org/). A elevada dinâmica do projeto, a sua extensibilidade através de módulos (JAVA ou Python), e ainda o acesso gratuito ao software fazem do Autopsy uma aplicação de referência no domínio das perícias de informática forense. Com o projeto Log Forensics for Autopsy (LFA) pretende-se o desenvolvimento de um módulo para o Autopsy que possibilite a deteção e validação de registos do sistema (log) e em particulares dos logs produzidos pelo sistema operativo Windows e aplicações em situações especiais, nomeadamente quando ocorre terminações abruptas. Exemplos desses logs são os existentes nos diretórios C:\ProgramData\Microsoft\Windows\WER, C:\Users\UTILIZADOR\AppData\Local\Microsoft\Windows\WER (em que UTILIZADOR corresponde a um login do sistema), C:\windows\LiveKernelReports e C:\windows\logs. O objetivo principal do projeto LFA é a criação de um módulo para Autopsy que seja capaz de extrair informação com valor forense dos logs acima indicados, bem como de outros similares. O módulo LFA deve estar preparado para análise ao sistemas operativos Windows 7, Windows 8 e Windows 10.
