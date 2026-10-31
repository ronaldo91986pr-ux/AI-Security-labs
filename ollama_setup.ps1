# Start Ollama service locally and verify API health
Write-Host "Checking local Ollama service health..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -Method Get
    Write-Host "Ollama service is running. Installed models:" -ForegroundColor Green
    $response.models | Select-Object name, size, modified_at | Format-Table -AutoSize
} catch {
    Write-Host "Ollama service not detected. Ensure 'ollama serve' is running." -ForegroundColor Red
}

# Pull specified local model
$targetModel = "llama2-uncensored"
Write-Host "Pulling target model: $targetModel..." -ForegroundColor Cyan
ollama pull $targetModel
