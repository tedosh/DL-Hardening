# (c) Copyright 2016 Autodesk Inc.
# Filename: DLMemberSizeHardening_v02.ps1
# Authors: Ted Osheroff
# Last Updated: July 11, 2016
#
# Purpose:
# Powershell script to find out all distribtion lists that have more than $memberCountLimit members, restrict them in exchange so that by default only owners of the list can send emailt to it.
# Other authorized senders can be added aftwerwards via MyDesk.
#
# Requirements:
# Script requires the ActiveDirectory powershell module installed.
# Script is dependant on Quest.ActiveRoles.ADManagementsnapin to write into ActiveRoles and Active Directory.
# The Quest.ActiveRoles.ADManagement snapin can be downloaded from'PowerShell Commands (CMDLETs) for Active Directory by Quest Software'(http://www.quest.com/powershell/activeroles-server.aspx)
# Look for ActiveRoles Management Shell for Active Directory (both32-bit or 64-bit versions available)
# This script must be run with a service account that has access to create distribution lists and modify them (or at least the needed attributes).

Add-PSSnapin Quest.ActiveRoles.ADManagement
import-module activedirectory
Set-QADPSSnapinSettings -DefaultSizeLimit 0

$date = Get-Date -uformat %m%d%Y_%I%M%p
$logname = "DL_Hardening_" + $date + ".txt"
$logpath = "C:\ARS Scripts PRD\Script_Logs\DL_Hardening\" + $logname
$newLine = "`n"

$date = Get-Date
$msg_date = "Begin DL Hardening Script" + ": " + $date
$msg_date |  Out-File $logpath
$newLine | Out-File $logpath -Append

######################
## Common variables ##
######################
$msg_scriptVariables = "*** Script Variables ***"
$msg_scriptVariables | Out-File $logpath -Append

$memberCountLimit = 500
$msg_memberCountLimit = "Groupmember threshold set to: " + $memberCountLimit
$msg_memberCountLimit | Out-File $logpath -Append

$sendersGroupOU = "OU=DL-RestrictedSenders,OU=Distribution,OU=Groups,OU=Objects,DC=ads,DC=autodesk,DC=com"
$msg_sendersGroupOU = "Location of AuthSenders OU: " + $sendersGroupOU
$msg_sendersGroupOU | Out-File $logpath -Append

$geoAuthorizedSenders = get-qadgroup -Identity world-authors
$msg_geoAuthorizedSenders = "Geo Authorized Senders Group: " + $geoAuthorizedSenders.DN
$msg_geoAuthorizedSenders | Out-File $logpath -Append

$AuthSendersRestriction = get-qadgroup -Identity AuthSendersRestriction
$msg_AuthSendersRestriction = "AuthSenders Restriction Group: " + $AuthSendersRestriction.DN
$msg_AuthSendersRestriction | Out-File $logpath -Append

$VPauthSenders = get-qadgroup -Identity vp.auth.new
$msg_VPauthSender = "VP Authsenders Group: " + $VPauthSenders.DN
$msg_VPauthSender | Out-File $logpath -Append
$newLine | Out-File $logpath -Append

$over500Count = $null
$dlists = $null

[string] $smtpServer = "smtp.autodesk.com"
#[string] $fromAddress="Ted Osheroff <ted.osheroff@autodesk.com>"
[string] $fromAddress="EIS Helpdesk <eis.distribution.list.management@autodesk.com>"
[string[]]$to = $null
[string[]]$cc = $null
[string[]]$ccaddress = $null
[string[]]$bcc = "Help Desk <help@autodesk.com>", "Ted Osheroff <ted.osheroff@autodesk.com>"

#For Testing
#[string[]] $to = "Ted Osheroff <ted.osheroff@autodesk.com>"
#[string[]] $to = "Ted Osheroff <ted.osheroff@autodesk.com>", "Emily Buskirk <emily.buskirk@autodesk.com>", "Jane Couch <Jane.Couch@autodesk.com>", "Hope Price <hope.price@autodesk.com>"
#[string[]]$ccAddress="Ted Osheroff <ted.osheroff@autodesk.com>", "Theo22 <theo_22@yahoo.com>"

###############
## Functions ##
###############
function SendEmail{
    $subject = "MyDesk Notification: an email list you own has reached 500 members, limiting who can send to it"
    $a = "<a href=https://mydesk.autodesk.com/main/#/do/emaillists target="" _blank"">MyDesk</a>"

    $body = "<HTML><HEAD><META http-equiv=""Content-Type"" content=""text/html; charset=iso-8859-1"" /><TITLE></TITLE></HEAD>"
    $body += "<BODY bgcolor=""#FFFFFF"" style=""font-size: Small; font-family: Calibri; color: #000000""><P>"
    $body += "Hello,<br>
    <br>This is a friendly reminder that you own, or co-own, an email list that has reached 500+ members,`
     and is therefore limited in who can send to it.  Only the list owner, co-owner, `
     and any &quot;authorized senders&quot; that you designate can send to a large (500+ member) email list.<br>
    <br>You can manage your email lists, including adding or removing `"authorized senders`", via $a.<br>
    <br>If you have questions or need assistance, please contact the EIS Helpdesk, +1 415-507-8888."
    
    <#Used for Testing
    #$to
    #$ccaddress
    #$bcc
    [string[]] $to = "Ted Osheroff <ted.osheroff@autodesk.com>"
    $to

    #Use for testing email.  Only send to me.
    Send-MailMessage -From $fromAddress -To $to -Subject $subject -Body $body -SmtpServer $smtpServer -BodyAsHtml
    #>
    
       #Comment out Send-MailMessage to not send email during testing.
       Send-MailMessage -From $fromAddress -To $to -Cc $ccaddress -Bcc $bcc -Subject $subject -Body $body -SmtpServer $smtpServer -BodyAsHtml
       $msg_sendEmail = "Email Sent for new Authsenders group."
       $msg_sendEmail | Out-File $logpath -Append
} #end sendmail funtion


function AuthsendersCheck{
    $msg_authSendersGroupExists = "Authsenders Group Exists: " + $authSendersGroup
    $msg_authSendersGroupExists | Out-File $logpath -Append
    $authsenders_members = $null

    #List the members of the Authsenders Group.
    #$authsenders_members = Get-QADGroupMember $authSendersGroup
                    
        If ($authsenders_members = Get-QADGroupMember $authSendersGroup){
            If ($authSenders_members -ne $null){
                $msg_AuthsendersMembers = "Member(s) of: " + $authSendersGroup
                $msg_AuthsendersMembers | Out-File $logpath -Append
                
                    foreach ($member in $authsenders_members) {
                        #For Testing.
                        #$member.name
                        $member.name | Out-File $logpath -Append
                    } #end foreach authsenders member
             } # end if authsenders -ne $null

             Else {
                $msg_noAuthsendersMembers = "*** ERROR *** There are no members in: " + $authSendersGroup
                $msg_noAuthsendersMembers | Out-File $logpath -Append
             } #end else no Authsenders members
        } #end if members of the authsenders Group.
} #end function AuthsendersCheck


function dlMemSubmitPermsCheck{
    $msg_groupDlMemSubmitPerms = "Checking dlMemSubmitPerms value for group : " + $group.Name + " .............."
    $msg_groupDlMemSubmitPerms | Out-File $logpath -Append

    #List the dlMemSubmitPerms value on the group that has over 500 members
    If ($group.dLMemSubmitPerms -ne $null){
        #$dlMemSubmitPermsList = $group.dLMemSubmitPerms
        foreach ($dlGroup in $group.dLMemSubmitPerms){
            $dlgroupName = Get-QADGroup $dlgroup
            $dlGroupName.name | Out-File $logpath -Append
        } #end foreach dlGroup
    } #end if dlMemSubmitPerms

        # Else dlMemSubmitPerms is blank, so add the Authsenders group.
        Else {
            $msg_nodlMemSubmitPerms = "*** ERROR *** dlMemSubmitPerms is empty." 
            $msg_nodlMemSubmitPerms | Out-File $logpath -Append

            #Set Existing Authsenders & vp.auth.new on DL#
            $authSendersGroupDN = Get-QADGroup $authSendersGroup            
            Set-QADGroup -Identity $group.DN -ObjectAttributes @{'dLMemSubmitPerms'= @{Append=@($authSendersGroupDN.DN,$VPauthSenders.DN)}} -proxy #-WhatIf
            $msg_setDLMemSubmitPers = "Setting dlMemSubmitPerms to: "
            $msg_setDLMemSubmitPers | Out-File $logpath -Append
            $authSendersGroupDN.DN | Out-File $logpath -Append
            $VPauthSenders.DN | Out-File $logpath -Append
        } #end Else no dlMemSubmitPerms
} #end function dlMemSubmitPermsCheck

#Break to check variable values.
#BREAK STATEMENT


##################
## Begin Script ##
##################

#[DEBUGGING] For Testing One Specific Group or an array of groups. Uncomment one line and comment the Prod lines below.
#$dlists = Get-QADGroup "EIS Server Owners" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "MCS FAM" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "MFG.FAM" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"} #This evaluates to 5 groups.
#$dlists = Get-QADGroup "Cloud Platforms Global" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "MAGIC Mentoring Participants" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "LUMA.Community" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "autodesk.research.friends" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "mfg.black.belt.team" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#For testing group that has Authsenders group but dlMemSubmitPers is empty.
#$dlists = Get-QADGroup "DMG All" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#For testing Authsenders when sAMAccoutName doesn't match
#$dlists = Get-QADGroup "LTDACG-Users" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#For testing Geo Groups
#$dlists = Get-QADGroup "geo.united.states.san.francisco.contingent" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}
#$dlists = Get-QADGroup "geo.japan.tokyo.regular.employee" -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms | Where-Object {$_.sAMAccountName -notmatch "-Authsenders"}

#[PROD] Get DL's in the domain
$dlists = get-qadgroup -GroupType Distribution -IncludedProperties extensionAttribute11,dLMemSubmitPerms `
-SearchRoot "DC=ADS,DC=autodesk,DC=com" `
-LdapFilter '(!(extensionAttribute11=Exception))' | Where-Object {$_.sAMAccountName -notmatch "-authsenders"} 
#>

#Iterate through dlists
$msg_dlists = "Total Number of Dist. Groups: " + $dlists.count
$msg_dlists | Out-File $logpath -Append
$newLine | Out-File $logpath -Append


foreach ($group in $dlists) {
    #For testing    
    #$group.Name  | Out-File $logpath -Append
    
    ##############################
    ## Reset Variables to $null ##
    ##############################
    $sourceGroupInfo = $null
    $authSendersGroup = $null
    $authSendersGroupDisplayName = $null
    $groupEmail = $null
    $groupDescription = $null
    $newAuthSendersGroup = $null

    #Check if its a "Geo" or "Staff" group before checking count of group members.
    #Geo and Staff lists will not generate a unique Authsenders group, the global Geo Authorized Senders group will be used.
    $groupSam = $group.sAMAccountName.ToLower()
       if (($groupSam.StartsWith("geo.")) -or ($groupSam.StartsWith("staff."))) {
            $newLine | Out-File $logpath -Append
            $group.Name  | Out-File $logpath -Append           
         
         #########################################################
         # Check if group over 500, if so, then perform next step.
         # Otherwise move on.
         #########################################################

            #Check if geoAuthSenders dlMemSubmitPerms attribute is set.
                if ($group.dLMemSubmitPerms -eq $geoAuthorizedSenders.DN) {
                    $msg_authSendersGroup = "Geo Authsenders group is set."
                    $msg_authSendersGroup | Out-File $logpath -Append
                } #end if geoAuthSenders dlMemSubmit attribute is set

                    else {
                        #Else: This is a Geo list and the geoAuthSender group is not set, so set it here.
                        Set-QADGroup -Identity $group.DN -ObjectAttributes @{dLMemSubmitPerms= @{Update = @($geoAuthorizedSenders.DN)}} -proxy #-WhatIf
                        $msg_geoAuthorizedSenders = "Geo Authsender Group was not set. Setting it to: " + $geoAuthorizedSenders.DN
                        $msg_geoAuthorizedSenders | Out-File $logpath -Append
                    } #end else Geo list geoAuthSender group is not set.
       } #end if Geo or Staff list  
       
       #Don't evaluate groups that end with -Authsenders.
       #May not need this anymore.  Trying to filter out -authsender groups in new filter above.
       elseif ($groupSam.EndsWith("-authsenders")){
            #Do nothing.  Don't check group membership
            
            #For Testing
            #$newLine | Out-File $logpath -Append
            #$group.Name  | Out-File $logpath -Append
            #$msg_authsendersGroupName = "This is an Authsenders Group.  Don't eval."
            #$msg_authsendersGroupName | Out-File $logpath -Append
       } #end else group.sAMAccountName end with -Authsenders     

       #Else this is not a Geo, Staff, or Authsenders Group.  Check if memberCount is over 500.  If so, take action!       
       else {
        #Get count of members in the group
        $memberCount = @(get-qadgroupmember -identity $group.sAMAccountName -Indirect).Count

        #For Testing
        #$memberCount | Out-File $logpath -Append

            #If membercount greater than 500, take action!
            If ($memberCount -gt $memberCountLimit) {  
                $to = $null
                $over500Count = ++$over500Count
                
                #Send timestamp and groupname to out file.
                $newLine | Out-File $logpath -Append
                $timeStamp = Get-Date -uformat %m/%d/%Y_%I:%M%p
                $timeStamp | Out-File $logpath -Append
                $group.Name  | Out-File $logpath -Append
            
                #Update extensionAttribute13 (member count) on dist. group object.
                Set-QADGroup -Identity $group.DN -ObjectAttributes @{'extensionAttribute13'=$memberCount} -proxy #-WhatIf
                $msg_groupCount = "Updated extensionAttribute13 (Member Count) -  "+ $memberCount
                $msg_groupCount | Out-File $logpath -Append


                ##############################################
                ## Check for existence of Authsenders Group ##
                ##############################################

                #Set the Authsenders group name using name & sAMAccountName.  Need to check
                #for both because our group naming standards are non-conforming.
                $msg_authSendersGroup = "Checking if Authsenders Group Exists................."
                $msg_authSendersGroup | Out-File $logpath -Append
                
                #Set $suthsendersGroup to either $group.name or $group.sAMAccountName
                #Search for -authsenders group for each name.
                #################################
                ## Check Using .sAMAccountName ##
                #################################
                $authSendersGroup = $group.sAMAccountName + "-AuthSenders"
                If (get-qadgroup -Identity $authSendersGroup -GroupType Distribution){
                    AuthsendersCheck
                    dlMemSubmitPermsCheck
                } #end if AuthsendersGroup Exist exist .sAMAccountName

                #######################
                ## Check Using .Name ##
                #######################
                 Else {
                    $authSendersGroup = $group.name + "-AuthSenders"

                    If(get-qadgroup -Identity $authSendersGroup -GroupType Distribution) {
                    AuthsendersCheck
                    dlMemSubmitPermsCheck
                    } #end if AuthsendersGroup exist .name
                 } #end else change AuthsendersGroup to .name


                ############################################################################################################
                ## Create new Authsenders group.  Continue with setting dlmem on DL and adding members to new Authsenders ##
                ############################################################################################################

                #AuthSenders Group Does not Exist, Create it!
                If (!(get-qadgroup -Identity $authSendersGroup -GroupType Distribution)){
                    $msg_authSendersGroupDoesNotExists = "Authsenders Group Does Not Exist. Creating Now................. "
                    $msg_authSendersGroupDoesNotExists | Out-File $logpath -Append
                                           
                    #Get the sourcegroup info needed for creating the Authsenders Group.
                    $sourceGroupInfo = Get-QADGroup -Identity $group.DN -IncludedProperties managedBy,edsvaSecondaryOwners,displayName,mail,dLMemSubmitPerms -GroupType Distribution -Proxy 
                                                  
                                #Set new Authsenders group displayName.
                                $authSendersGroupDisplayName = $group.Name + "-Authsenders"
                             
                                #Set new Authsenders group mail address.
                                $groupEmail = "Authsenders-" + $sourceGroupInfo.mail
                                $msg_groupEmail = "Creating groupEmail: " + $groupEmail
                                $msg_groupEmail | Out-File $logpath -Append
                            
                                #Set new Authsenders group Description.          
                                $groupDescription = "Authorized senders for Dlist " + $sourceGroupInfo.displayName
                                $msg_groupDescription = "Creating groupDescription: " + $groupDescription
                                $msg_groupDescription | Out-File $logpath -Append

                                #Create the new Authsenders Group
                                New-QADGroup -Name $authSendersGroupDisplayName -DisplayName $authSendersGroupDisplayName -GroupType 'Distribution' `
                                -GroupScope 'Universal' -Description $groupDescription -sAMAccountName $authSendersGroupDisplayName -Email $groupEmail `
                                -ParentContainer $sendersGroupOU -ObjectAttributes @{msExchHideFromAddressLists=$True} #-WhatIf

                                $newAuthSendersGroup = Get-QADGroup -Name $authSendersGroupDisplayName

                                $msg_newAuthSenderGroup = "New AuthSenders Group created: $authSendersGroupDisplayName"
                                $msg_newAuthSenderGroup | Out-File $logpath -Append

                                #Break to check variable values during testing.
                                #BREAK STATEMENT
                                
                                ################################################################################
                                ## Get addresses for sending email notification.  Only send if manager exist. ##
                                ################################################################################
                                #If ($group.ManagedBy -ne $null){
                                If ($sourceGroupInfo.ManagedBy -ne $null){
                                    $manager = $sourceGroupInfo.ManagedBy
                                    $managermail = get-qaduser $manager -IncludedProperties mail
                                    If ( $managermail -ne $null){
                                        $to = $managermail.mail

                                        $msg_manageremail = "Mail Addressed To Manager: " + $to 
                                        $msg_manageremail | Out-File $logpath -Append
                                    }
                                    #$to
                                    
                                    #If no manager exists for To: address then log error and don't worry about checking secondaries.
                                    If ($to -ne $null) {
                                        If ($sourceGroupInfo.edsvaSecondaryOwners -ne $null){
                                                Foreach ($secondary in $sourceGroupInfo.edsvaSecondaryOwners){
                                                    If ($secondary -ne $sourceGroupInfo.ManagedBy){
                                                        $user = Get-QADUser $secondary -IncludedProperties mail
                                                        $cc += $user.mail   
                                                        $ccaddress = $cc -join "," 

                                                        $msg_secondaryemail = "Mail CC: " + $cc 
                                                        #$msg_secondaryemail | Out-File $logpath -Append
                                                    }#end If $secondary -ne $sourceGroupInfo.ManagedBy
                                                } #end for each secondary in dlists.
                                                $msg_secondaryemail | Out-File $logpath -Append
                                        } #end if edsvaSecondaryOwners -ne null.

                                            Else {
                                                $msg_nosecondaryforemail = "*** ERROR *** " + $group.name + ": No secondary owners to send email to." 
                                                $msg_nosecondaryforemail | Out-File $logpath -Append
                                            }#end else no secondaries
                                    }#end if $to not null

                                    #Create and send email for new Authsenders group.
                                    SendEmail($to, $ccaddress)

                               } #end If manager exist

                               Else {
                                    $msg_nomanagerforemail = "*** ERROR *** " + $group.name + ": No manager to send email to. No email sent for new Authsenders group." 
                                    $msg_nomanagerforemail | Out-File $logpath -Append
                               } #end else no manager

                                
                                #########################################################################################################################
                                ## Add the new AuthSenders group and the VP Authsenders group to the dLMemSubmitPerms attribute of the original group. ##
                                #########################################################################################################################
                                try {
                                    #Used for testing when specifically setting the Dlist above to one group.
                                    #$newAuthSendersGroup = Get-QADGroup "LUMA Community-Authsenders" -IncludedProperties extensionAttribute11,dLMemSubmitPerms

                                    
                                    #$authSendersGroupDN = Get-QADGroup $newAuthSendersGroup 
                                    Set-QADGroup -Identity $sourceGroupInfo.DN -ObjectAttributes @{'dLMemSubmitPerms'= @{Update = @($newAuthSendersGroup.DN, $VPauthSenders.DN)}} -proxy #-WhatIf
                                    
                                    if ($sourceGroupInfo.DisplayName -eq $null){
                                        $msg_noSourceGroupDisplayName = "*** ERROR *** " + $sourceGroupInfo.sAMAccountName + " does not have a displayName."
                                        $msg_noSourceGroupDisplayName | Out-File $logpath -Append
                                    } #end if no displayName on sourcegroup

                                    $msg_authSendersGroupDN = "Added the AuthSenders & VP Authsenders groups to the dlMemSubmitPerms attribute of: " + $sourceGroupInfo.DisplayName
                                    $msg_authSendersGroupDN | Out-File $logpath -Append
                                } #end try

                                    catch {
                                        $msg_noGroupMgr = "*** ERROR *** AuthSenders & VP Authsenders groups not added to the dlMemSubmitPerms attribute of: " + $sourceGroupInfo.DisplayName.
                                        $msg_noGroupMgr | Out-File $logpath -Append
                                    } #end catch


                                ##############################################################################################################
                                ## Add the manager & secondaries of the group that has over 500 members, as member to new Authsender group. ##
                                ##############################################################################################################
                                If ($sourceGroupInfo.ManagedBy -ne $null){                                
                                    Add-QADGroupMember -Identity $newAuthSendersGroup -Member $sourceGroupInfo.managedBy
                                    $msg_AddMember = "Added Manager of " + $sourceGroupInfo.name + " as Group Member to new Authsenders group: " + $sourceGroupInfo.managedBy
                                    $msg_AddMember | Out-File $logpath -Append
                                } #end if $group.managedBy

                                Else {
                                    $msg_noGroupMgr = "*** ERROR *** No Group Manager Found on Corresponding DL. Not Added as Group Member to Authsendsers Group."
                                    $msg_noGroupMgr | Out-File $logpath -Append
                                } #end else no group manager

                                If ($sourceGroupInfo.ManagedBy -ne $null) {
                                        If ($sourceGroupInfo.edsvaSecondaryOwners -ne $null){ 
                                        #Add the secondary owners (secondary manager(s)) of the group that has over 500 members, as members to new Authsender group.
                                            foreach ($secondaryOwner In $sourceGroupInfo.edsvaSecondaryOwners) {
                                                If ($secondaryOwner -ne $sourceGroupInfo.ManagedBy){
                                                    Add-QADGroupMember -Identity $newAuthSendersGroup -Member $secondaryOwner
                                                    $msg_AddSecondaryOwners = "Added Secondary Owner as Group Member: " + $secondaryOwner
                                                    $msg_AddSecondaryOwners | Out-File $logpath -Append
                                                }#end If $secondary -ne $sourceGroupInfo.ManagedBy
                                            } #end foreach secondary owner
                                        } #end if secondary owners found

                                        Else {
                                            $msg_noAddSecondaryOwners = "*** ERROR *** No Secondary Owners Found on Corresponding DL.  None Added as Members to Authsendsers Group."
                                            $msg_noAddSecondaryOwners | Out-File $logpath -Append
                                        } #end else no secondaryOwners
                                } #end if $group.managedBy
                    } #end else AuthSenders Group Does not Exist.      
             } #end if membercount greater than 500.
       } #end else this is not a Geo or Staff list.
} #end beginning foreach.

$newLine | Out-File $logpath -Append  
$msg_over500Count = "There are " + $over500Count + " groups with over 500 members."
$msg_over500Count | Out-File $logpath -Append

$date = Get-Date
$newLine | Out-File $logpath -Append
$msg_date = "End DL Hardening Script" + ": " + $date
$msg_date |  Out-File $logpath -Append
