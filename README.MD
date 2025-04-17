Download dotnet

open powershell as admin and navigate to folder where you unpacked this

type ```dotnet restore```

Edit program.cs in notepad and replace api key with your own (it's free, just open account at virustotal)

type ```dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true```
