#!/bin/bash
# Build and push IRIS module to containers (Podman-compatible)
# Based on https://docs.dfir-iris.org/latest/development/modules/quick_start/buildnpush2iris.sh
# Adapted for Podman (works with Docker too)

set -e

CONTAINER_RT=$(command -v podman || command -v docker)
if [ -z "$CONTAINER_RT" ]; then
    echo "ERROR: Neither podman nor docker found"
    exit 1
fi

Help()
{
   echo "Build IRIS module and install it into the IRIS containers."
   echo
   echo "Syntax: $0 [-a|h][-w NAME][-p NAME]"
   echo "options:"
   echo " -a         Also install to the app container (required on first install or config changes)"
   echo " -w NAME    Worker container name (default: iriswebapp_worker)"
   echo " -p NAME    App container name (default: iriswebapp_app)"
   echo " -h         Print this help"
   echo
}

CheckPrerequisite()
{
    PYTHON=$(command -v python3 || command -v python)
    if [ -z "$PYTHON" ]; then
        echo "ERROR: Python could not be found"
        exit 1
    fi

    if ! $PYTHON -m pip --version > /dev/null 2>&1; then
        echo "ERROR: pip could not be found"
        exit 1
    fi
}

Run()
{
    CheckPrerequisite

    echo "[BUILDnPUSH2IRIS] Starting the build and push process.."

    $PYTHON -m pip wheel . --no-deps -w dist/

    # Find the most recently built wheel
    latest=$(ls -Art1 ./dist/*.whl | tail -n 1)
    module=$(basename "$latest")

    echo "[BUILDnPUSH2IRIS] Found latest module file: $latest"

    echo "[BUILDnPUSH2IRIS] Copy module file to worker container.."
    $CONTAINER_RT cp "$latest" "$worker_container_name:/iriswebapp/dependencies/$module"

    echo "[BUILDnPUSH2IRIS] Ensuring pycti is installed in worker container.."
    $CONTAINER_RT exec "$worker_container_name" pip3 install "pycti>=6.0,<7.0" --quiet

    echo "[BUILDnPUSH2IRIS] Installing module in worker container.."
    $CONTAINER_RT exec "$worker_container_name" pip3 install "dependencies/$module" --no-deps --force-reinstall

    echo "[BUILDnPUSH2IRIS] Restarting worker container.."
    $CONTAINER_RT restart "$worker_container_name"

    if [ "$a_Flag" = true ] ; then
        echo "[BUILDnPUSH2IRIS] Copy module file to app container.."
        $CONTAINER_RT cp "$latest" "$app_container_name:/iriswebapp/dependencies/$module"

        echo "[BUILDnPUSH2IRIS] Ensuring pycti is installed in app container.."
        $CONTAINER_RT exec "$app_container_name" pip3 install "pycti>=6.0,<7.0" --quiet

        echo "[BUILDnPUSH2IRIS] Installing module in app container.."
        $CONTAINER_RT exec "$app_container_name" pip3 install "dependencies/$module" --no-deps --force-reinstall

        echo "[BUILDnPUSH2IRIS] Restarting app container.."
        $CONTAINER_RT restart "$app_container_name"
    fi

    # Restart nginx so it resolves the new container IPs after restart
    echo "[BUILDnPUSH2IRIS] Restarting nginx container.."
    $CONTAINER_RT restart "$nginx_container_name"

    echo "[BUILDnPUSH2IRIS] Completed!"
}

a_Flag=false
worker_container_name="iriswebapp_worker"
app_container_name="iriswebapp_app"
nginx_container_name="iriswebapp_nginx"

while getopts ":haw:p:" option; do
   case $option in
      h) Help; exit;;
      a) a_Flag=true;;
      w) worker_container_name=$OPTARG;;
      p) app_container_name=$OPTARG;;
      \?) echo "ERROR: Invalid option"; exit 1;;
      :) echo "ERROR: Option -$OPTARG requires an argument."; exit 1;;
   esac
done

if [ "$a_Flag" = true ] ; then
    echo "[BUILDnPUSH2IRIS] Pushing to Worker and App container!"
else
    echo "[BUILDnPUSH2IRIS] Pushing to Worker container only!"
fi

Run
