#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepositoryPath,[string]$OutputPath)

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Supply_Chain_Security_Research'}
New-Item -Path $OutputPath -ItemType Directory -Force|Out-Null
if(-not(Test-Path $RepositoryPath)){Write-Error 'Repository path not found.';return}

$files=Get-ChildItem -Path $RepositoryPath -Recurse -File -ErrorAction SilentlyContinue
$indicators=[System.Collections.Generic.List[object]]::new()
function Add-Indicator{param($Control,$Status,$Evidence,$Recommendation)
 $indicators.Add([PSCustomObject]@{Control=$Control;Status=$Status;Evidence=$Evidence;Recommendation=$Recommendation})
}

$manifests=$files|Where-Object{$_.Name -in @('package.json','requirements.txt','pyproject.toml','Pipfile','pom.xml','build.gradle','packages.config','go.mod','Cargo.toml')}
$lockFiles=$files|Where-Object{$_.Name -in @('package-lock.json','yarn.lock','pnpm-lock.yaml','Pipfile.lock','poetry.lock','go.sum','Cargo.lock')}
$sbom=$files|Where-Object{$_.Name -match 'sbom|bom\.json|bom\.xml' -or $_.Extension -eq '.spdx'}
$workflows=$files|Where-Object{$_.FullName -match '[\\/]\.github[\\/]workflows[\\/].+\.ya?ml$'}
$securityDocs=$files|Where-Object{$_.Name -in @('SECURITY.md','CODEOWNERS','DEPENDABOT.yml','dependabot.yml')}

Add-Indicator 'Dependency manifest present' $(if($manifests){'Pass'}else{'Info'}) ($manifests.Name -join '; ') 'Document dependency sources and ownership.'
Add-Indicator 'Dependency lock file present' $(if($lockFiles){'Pass'}else{'Review'}) ($lockFiles.Name -join '; ') 'Use supported lock files for reproducible builds.'
Add-Indicator 'SBOM present' $(if($sbom){'Pass'}else{'Review'}) ($sbom.Name -join '; ') 'Generate and publish an SBOM for releases.'
Add-Indicator 'Security policy present' $(if($files.Name -contains 'SECURITY.md'){'Pass'}else{'Review'}) 'SECURITY.md' 'Add a vulnerability reporting and support policy.'
Add-Indicator 'CODEOWNERS present' $(if($files.Name -contains 'CODEOWNERS'){'Pass'}else{'Review'}) 'CODEOWNERS' 'Define ownership for sensitive files and workflows.'
Add-Indicator 'Automated workflows present' 'Info' "Workflow count=$(@($workflows).Count)" 'Review workflow permissions and third-party action pinning.'

$workflowReview=foreach($workflow in $workflows){
 $content=Get-Content $workflow.FullName -Raw -ErrorAction SilentlyContinue
 [PSCustomObject]@{
  File=$workflow.FullName.Substring($RepositoryPath.TrimEnd('\').Length).TrimStart('\')
  HasPermissionsBlock=[bool]($content -match '(?m)^permissions:')
  UsesThirdPartyActions=[bool]($content -match 'uses:\s*(?!actions/)[^\s]+')
  UsesCommitShaPin=[bool]($content -match 'uses:\s*[^@\s]+@[0-9a-fA-F]{40}')
 }
}

$summary=[PSCustomObject]@{Repository=(Resolve-Path $RepositoryPath).Path;Files=@($files).Count;Manifests=@($manifests).Count;LockFiles=@($lockFiles).Count;Workflows=@($workflows).Count;SBOMFiles=@($sbom).Count;Generated=Get-Date}
$indicators|Export-Csv (Join-Path $OutputPath "research_findings_$stamp.csv") -NoTypeInformation -Encoding UTF8
$workflowReview|Export-Csv (Join-Path $OutputPath "workflow_review_$stamp.csv") -NoTypeInformation -Encoding UTF8
@{Summary=$summary;Findings=$indicators;WorkflowReview=$workflowReview}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath "supply_chain_research_$stamp.json") -Encoding UTF8
$html="<h1>Software Supply Chain Security Research</h1><p>Generated $(Get-Date)</p><h2>Summary</h2>$(@($summary)|ConvertTo-Html -Fragment)<h2>Findings</h2>$($indicators|ConvertTo-Html -Fragment)<h2>Workflow Review</h2>$($workflowReview|ConvertTo-Html -Fragment)"
$html|ConvertTo-Html -Title 'Software Supply Chain Security Research'|Set-Content (Join-Path $OutputPath "supply_chain_research_$stamp.html") -Encoding UTF8
$summary|Format-List
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
