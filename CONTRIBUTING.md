# How to contribute?
You can contribute to this repo by reporting bugs, suggesting enhancements and fixing documentation. Here's how to do it:

- Go to [issues](https://github.com/rdbo/libmem/issues/new) page
- Give a descriptive title. It should have this format. `[Bug]: Title`
- Add a description explaining the issue. You should give a detailed explanation. For example, the button on the website has a bright color which makes it hard to see the text in it.
- Add screenshots if available



# How to submit a pull request
**1.** [Fork](https://github.com/rdbo/libmem/fork) the GitHub repository.

**2.** Clone the forked repository.

```bash
git clone https://github.com/<your-username>/libmem.git)
```

**3.** Navigate to the project directory.

```bash
cd libmen
```

**4.** Follow libmem's coding style as much as you can (especially when aligning things)

**5.** Stage your changes and commit.

```bash
git add . # Stages all the changes
git commit -m "<your_commit_message>"
```
**6.** Push your local commits to the remote repository.
```bash
git checkout -b your-branch-name
```

```bash
git push origin your-branch-name
```
**7.** Create a new [pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request). Submit a pull request containing a description of what the pull request does, and how it does so

### **NOTE**

LEGAL: Every commit submitted through a pull request must be under the same license as libmem (in this case, the GNU AGPLv3.0)
- In case of creating new source code files, make sure to put the following license:


        /*
         * Copyright (C) <year>    <contributor(s)>
         * This program is free software: you can redistribute it and/or modify
         * it under the terms of the GNU Affero General Public License as
         * published by the Free Software Foundation, either version 3 of the
         * License, or (at your option) any later version.
         *
         * This program is distributed in the hope that it will be useful,
         * but WITHOUT ANY WARRANTY; without even the implied warranty of
         * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
         * GNU Affero General Public License for more details.
         *
         * You should have received a copy of the GNU Affero General Public License
         * along with this program.  If not, see <https://www.gnu.org/licenses/>.
         */
