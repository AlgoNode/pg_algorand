#!/bin/bash
plgo
docker build . -t urtho/pg14algorand
docker push urtho/pg14algorand:latest
