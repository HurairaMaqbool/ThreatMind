$container = docker ps -a -q -f "name=*autothreat*" | Select-Object -First 1

if ($container) {
    Write-Host "Found existing container $container. Extracting files..."
    docker cp ${container}:/app/agents .
    docker cp ${container}:/app/utils/groq_client.py ./utils/
    Write-Host "Recovery complete!"
} else {
    Write-Host "Could not find autothreat container. Let's try image."
    $image = docker images -q *autothreat* | Select-Object -First 1
    if ($image) {
        Write-Host "Found image $image. Creating temporary container to extract files..."
        docker create --name temp_restore $image
        docker cp temp_restore:/app/agents .
        docker cp temp_restore:/app/utils/groq_client.py ./utils/
        docker rm temp_restore
        Write-Host "Recovery complete!"
    } else {
        Write-Host "Could not find any Docker container or image to recover from. Please restore from Local History in VSCode."
    }
}
