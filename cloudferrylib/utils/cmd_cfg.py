# Copyright (c) 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and#
# limitations under the License.

from console_cmd import BC
__author__ = 'mirrorcoder'

cd_cmd = BC("cd %s")
qemu_img_cmd = BC("qemu-img %s")
move_cmd = BC("mv -f %s %s")
move_with_cd_cmd = cd_cmd & move_cmd
grep_cmd = BC("grep %s")
rbd_cmd = BC("rbd %s")
base_ssh_cmd = BC("ssh %s")
ssh_cmd = base_ssh_cmd("-oStrictHostKeyChecking=no %s '%s'")