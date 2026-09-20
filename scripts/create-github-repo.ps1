$body = @{
    name = 'termigo-security-kit'
    description = 'Termigo Security Kit - SAST, Dependency Audit, AV/Malware Scanner'
    private = $false
    auto_init = $false
} | ConvertTo-Json

$headers = @{
    Authorization = 'Bearer ' + $env:GH_TOKEN
    'User-Agent'  = 'termigo-agent'
}

$response = Invoke-RestMethod `
    -Uri 'https://api.github.com/user/repos' `
    -Method Post `
    -Headers $headers `
    -Body $body `
    -ContentType 'application/json'

Write-Host "Created repo:" $response.html_url
