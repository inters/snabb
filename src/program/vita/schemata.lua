-- Use of this source code is governed by the GNU Affero General Public License
-- as published by the Free Software Foundation, either version 3 or (at your
-- option) any later version; see src/program/vita/COPYING.

module(...,package.seeall)

local yang = require("lib.yang.yang")

yang.add_schema(require("program.vita.vita_esp_gateway_yang",
                        "program/vita/vita-esp-gateway.yang"))
yang.add_schema(require("program.vita.vita_ephemeral_keys_yang",
                        "program/vita/vita-ephemeral-keys.yang"))

return {
   ['esp-gateway'] =
      yang.load_schema_by_name('vita-esp-gateway'),
   ['ephemeral-keys'] =
      yang.load_schema_by_name('vita-ephemeral-keys')
}
