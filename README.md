## Утилита для проверки наличия установленного обновления MS17-010

Утилита позволяет быстро провести анализ сети на наличие хостов, на которых отсутствует обновление [MS17-010](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx). Это обновление закрывает уязвимости [CVE-2017-0143](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143), [CVE-2017-0144](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144), [CVE-2017-0145](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0145), [CVE-2017-0146](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0146), [CVE-2017-0147](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0147) и [CVE-2017-0148](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0148), часть и которых используются в эксплоите [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue). В частности, данную уязвимость эксплуатирует [Wana decrypt0r](https://gist.github.com/rain-1/989428fa5504f378b993ee6efbc0b168).

### Способы проверки

##### 1. Проверка через WMI

```
wmic qfe get HotFixID | findstr /c:4012212 /c:4012213 /c:4012214 /c:4012215 /c:4012216 /c:4012217 /c:4012598 /c:4012606 /c:4013198 /c:4013429
```

Есть есть результат выполнения этой команды, то обновление MS17-010 у вас установлено. В некоторых случаях WMI запрос не находит все установленные обновления. Это связано с тем, что класс Win32_QuickFixEngineering возвращает только те обновления, которые установлены с использованием [Component Based Servicing (CBS)](https://blogs.technet.microsoft.com/askperf/2008/04/23/understanding-component-based-servicing/). Те обновления, которые установлены с помощью Microsoft Windows Installer (MSI) или с сайта обновлений Windows, не детектируются через WMI. Поэтому есть следующий способ проверки установленных обновлений:

##### 2. Проверка через обращение к службе Windows Update (PowerShell)

```powershell
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$HistoryCount = $Searcher.GetTotalHistoryCount()
$Updates = $Searcher.QueryHistory(0, $HistoryCount)
Foreach ($item in $Updates) {
    if ($item.Title -match "4012212|4012213|4012214|4012215|4012216|4012217|4012598|4012606|4013198|4013429") {
        Write-Host 'MS17-010 installed'
    }
}
```

### ms17010.ps1
Изложенные выше способы проверки наличия установленного обновления MS17-010 были использованы при написании скрипта ms17010.ps1. Для удаленного подключения к службе WMI используется команда [Get-WmiObject](https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.management/get-wmiobject), а для удаленного подключения к локальной службе Windows Update используется [Windows Remote Management (WinRM)](https://msdn.microsoft.com/ru-ru/library/aa384426(v=vs.85).aspx). Если на удаленном узле не сконфигурирована служба WinRM, то проверка осуществляется только через WMI. Функции сканирования сети была заимствованы из пакета [LazyAdmin](https://github.com/BornToBeRoot/PowerShell).

##### Использование ms17010.ps1

1. Сканирует заданную сеть на наличие установленного обновления MS17-010 с использованием текущей учетной записи пользователя.
```powershell
.\rvision-ms17010.ps1 -StartIPv4Address 10.0.0.0 -EndIPv4Address 10.0.0.254
```
2. Если текущая учетная запись не имеет доступна к WMI, то есть возможность запустить скрипт от имени другого пользователя:
```powershell
.\rvision-ms17010.ps1 -StartIPv4Address 10.0.0.0 -EndIPv4Address 10.0.0.254 -UseCredentials
```

Пример использования скрипта:
```powershell
PS C:\> .\rvision-ms17010.ps1 -StartIPv4Address 10.0.0.0 -EndIPv4Address 10.0.0.254 -UseCredentials

IPv4Address                         Hotfix                                  Hostname
-----------                         ------                                  --------
10.0.0.2                            Ok                                      dc1.int.lan
10.0.0.3                            *** NOT INSTALLED ***                   dc2.int.lan
10.0.0.5                            Ok                                      sqldb.int.lan
10.0.0.12                           *** NOT INSTALLED ***                   si.int.lan
10.0.0.15                           *** NOT INSTALLED ***                   sp.int.lan
10.0.0.16                           *** NOT INSTALLED ***                   siem.int.lan
10.0.0.254                          *** NOT INSTALLED ***                   WIN2K12R2EN
10.0.0.246                          *** NOT INSTALLED ***                   WIN10EN32
10.0.0.247                          *** NOT INSTALLED ***                   WIN10EN64
10.0.0.245                          Ok                                      WIN10RU64
10.0.0.4                            *** NOT INSTALLED ***                   mail.int.lan
10.0.0.241                          *** NOT INSTALLED ***                   WIN7RU32
10.0.0.242                          Ok                                      WIN7EN32
10.0.0.14                           Ok                                      fp.int.lan
10.0.0.235                          *** NOT INSTALLED ***                   WIN8EN64
```

Чтобы отобразить статус подключения к службе WinRM, необходимо добавить аргумент -IncludeWinRM
```powershell
.\rvision-ms17010.ps1 -StartIPv4Address 10.0.0.0 -EndIPv4Address 10.0.0.254 -UseCredentials -IncludeWinRM
```

##### Ошибки в процессе выполнения скрипта

```
.\rvision-ms17010.ps1 : File C:\ms17-010-master\rvision-ms17010.ps1 cannot be loaded. The file C:\ms17-010-master\rvisi
on-ms17010.ps1 is not digitally signed. You cannot run this script on the current system. For more information about ru
nning scripts and setting execution policy, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=1351
70.
At line:1 char:1
+ .\rvision-ms17010.ps1 -StartIPv4Address 10.0.0.0 -EndIPv4Address 10.0.0.254
+ ~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess
```

Исправляется путем выполнения команды ```Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass```
