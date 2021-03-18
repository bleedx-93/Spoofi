# Spoofi
A simple tool to inject shellcode into the remote process.<br/>

Features:<br/> 
              - Parent Process Spoofing<br/>
              - Injection through APC<br/>
              - Dynamic API resolution<br/>


How to Use:<br/>
            1- Insert your shellcode in the shellcode variable<br/>
            2- Put your desired process full path in TargetProcess variable (Default value: "C:\\Program Files\\internet explorer\\iexplore.exe")<br/>
            3- Put your desired parent process in ParentProcess variable (Default value: "explorer.exe")<br/>
            4- Compile it<br/>
            5- Execute it through CommandLine<br/>
