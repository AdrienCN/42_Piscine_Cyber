#!/bin/bash

docker run -d -p 80:80 onion | xargs -I'{}' -o docker exec -it {} /bin/bash