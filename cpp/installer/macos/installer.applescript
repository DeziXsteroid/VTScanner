on chooseText(langCode, ruText, enText)
	if langCode is "ru" then
		return ruText
	end if
	return enText
end chooseText

on runShell(commandText)
	try
		do shell script commandText
	on error errText number errNum
		if errNum is 1 or errNum is 13 or errNum is 10004 then
			do shell script commandText with administrator privileges
		else
			error errText number errNum
		end if
	end try
end runShell

on run
	set languageChoice to choose from list {"Русский", "English"} with prompt "Выберите язык установщика / Choose installer language" default items {"Русский"} OK button name "Continue" cancel button name "Cancel" without empty selection allowed
	if languageChoice is false then
		return
	end if
	
	set langCode to "ru"
	if item 1 of languageChoice is "English" then
		set langCode to "en"
	end if
	
	set appName to "Network Tools 1.0.8"
	set bundlePath to POSIX path of (path to me)
	set resourcesPath to bundlePath & "Contents/Resources/"
	set payloadAppPath to resourcesPath & "payload/Network Tools 1.0.8.app"
	set payloadManufPath to resourcesPath & "payload/manuf"
	set targetFolder to choose folder with prompt (my chooseText(langCode, "Выберите папку установки приложения.", "Choose the application destination folder.")) default location path to applications folder
	set installDir to POSIX path of targetFolder
	set targetAppPath to installDir & appName & ".app"
	set supportDataDir to POSIX path of (path to library folder from user domain) & "Application Support/NetWorkTools/data"
	set desktopLinkPath to POSIX path of (path to desktop folder) & appName & ".app"
	set yesText to my chooseText(langCode, "Да", "Yes")
	set noText to my chooseText(langCode, "Нет", "No")
	set installText to my chooseText(langCode, "Установить", "Install")
	set closeText to my chooseText(langCode, "Закрыть", "Close")
	set openText to my chooseText(langCode, "Открыть", "Open")
	set shortcutReply to display dialog (my chooseText(langCode, "Создать ярлык приложения на рабочем столе?", "Create a desktop shortcut for the application?")) buttons {noText, yesText} default button yesText
	set createShortcut to false
	if button returned of shortcutReply is yesText then
		set createShortcut to true
	end if
	
	display dialog ((my chooseText(langCode, "Приложение будет установлено в:", "The application will be installed to:")) & return & targetAppPath) buttons {closeText, installText} default button installText
	
	my runShell("rm -rf " & quoted form of targetAppPath & " && ditto " & quoted form of payloadAppPath & " " & quoted form of targetAppPath)
	do shell script "mkdir -p " & quoted form of supportDataDir
	do shell script "cp -f " & quoted form of payloadManufPath & " " & quoted form of (supportDataDir & "/manuf")
	
	if createShortcut then
		do shell script "rm -f " & quoted form of desktopLinkPath & " && ln -s " & quoted form of targetAppPath & " " & quoted form of desktopLinkPath
	end if
	
	set finishReply to display dialog (my chooseText(langCode, "Установка завершена.", "Installation completed.")) buttons {closeText, openText} default button openText
	if button returned of finishReply is openText then
		do shell script "open " & quoted form of targetAppPath
	end if
end run
