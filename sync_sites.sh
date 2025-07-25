#!/bin/bash

cd ~/mobyphish_summer25/frontend || exit

for site in */; do
    # Remove trailing slash
    site_clean="${site%/}"

    # Normalize: lowercase + remove spaces
    site_target=$(echo "$site_clean" | tr '[:upper:]' '[:lower:]' | tr -d ' ')

    src_path="$PWD/$site_clean"
    dest_path="/var/www/$site_target/html"

    if [ -d "$dest_path" ]; then
        echo "✅ Copying: $site_clean → $dest_path"
        sudo cp -r "$src_path/"* "$dest_path/"
    else
        echo "❌ Skipped: $dest_path does not exist"
    fi
done
