-- Use of this source code is governed by the GNU Affero General Public License
-- as published by the Free Software Foundation, either version 3 or (at your
-- option) any later version; see src/program/vita/COPYING.

module(...,package.seeall)

local yang = require("lib.yang.yang")

return {
   ['esp-gateway'] =
      yang.load_schema_by_name('vita-esp-gateway', nil, "program.vita"),
   ['ephemeral-keys'] =
      yang.load_schema_by_name('vita-ephemeral-keys', nil, "program.vita")
}
