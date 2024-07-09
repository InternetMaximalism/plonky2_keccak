#!/bin/bash

original_dir="original"
changed_dir="../src/keccak_stark"
result_dir="result"

for original_file in "$original_dir"/*; do
  filename=$(basename "$original_file")
  changed_file="$changed_dir/$filename"
  diff "$original_file" "$changed_file" > "$result_dir/$filename.diff"
done
