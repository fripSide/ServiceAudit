## Table of Contents
- [Introduction](#introduction)
- [Build Project](#build-project)
- [Documents](#documents)
- [Analysis Results](#analysis-results)

## Introduction
This project is the source code for Android Service Helper bypass static analysis tool.

If there are any questions, please feel free to add issues.

## Build Project
1.Prepare to run project in 1 minute
  ```bash

  git clone https://github.com/fripSide/ServiceAudit.git
  cd ServiceAudit/bin
  # in Windows
  java -cp soot-dev.jar;ServiceAudit.jar com.serviceaudit.snk.Main conf.json
  # in Linux
  java -cp soot-dev.jar:ServiceAudit.jar com.serviceaudit.snk.Main conf.json
  ```

The results will be generated in `bin\results`.

2.Build project in 5 minutes
``` bash
mvn package
```

The build target will be generated to `bin\ServiceAudit.jar`.

## Documents
There are some supplemental documents for the approaches described in the Journal paper:
- Steps for extract the Extended SDK from Android Image [doc1](docs/1.extract_service_jar.md)
- System service extraction [doc2](docs/2.extract_ipc_methods.md)
- Results of NLP approach [doc3](docs/3.nlp_approach.md)
- Analysis results and vulnerabilities detail [doc4](docs/4.vulnerabilities.md)

## Analysis Results
After running the project, a short report will be print in the console and the vulnerability list will be generated to `results/report.txt`. Vulnerabilities details are shown in `results/vulnerable_api.json`.
