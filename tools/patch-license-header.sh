#!/bin/sh

if [ $# -ne 1 ]; then
    echo "missing file argument"
    exit 1
fi

perl -i -p0e 's|Copyright.*?/>.|Copyright (C) 2023    Rdbo\n * This program is free software: you can redistribute it and/or modify\n * it under the terms of the GNU Affero General Public License version 3\n * as published by the Free Software Foundation.\n * \n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU Affero General Public License for more details.\n * \n * You should have received a copy of the GNU Affero General Public License\n * along with this program.  If not, see <https://www.gnu.org/licenses/>.|s' "$1"
