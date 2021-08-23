#!/usr/bin/env python

import util
import logging
import os
import fcntl
try:
    from collections import defaultdict
except:
    from defaultdict_pure import defaultdict

def hgcmd(cmd):
    logger = logging.getLogger(__name__)
    result=util.call2(cmd)
    result.cmd=cmd
    logger.debug("cmd: %s; out: %s; err: %s; returncode: %d", result.cmd, result.out, result.err, result.returncode)
    return result

class HgError(Exception):
    pass

class Rev(object):
    def __init__(self,rev,dict_args={},**args):
        self.rev=rev
        self.__dict__.update(dict_args)
        self.__dict__.update(args)

    def __contains__(self, key):
        return (key in self.__dict__)

class Repo(object):

    @staticmethod
    def get_root(path):
        os.environ["HGPLAIN"] = "1"
        result = util.call2("hg --cwd %s root" % path)
        if result.returncode != 0:
            raise HgError("Failed to get root of repository! %s %s" % (result.out, result.err))
        else:
            return result.out

    def __init__(self, path, create=False):
        self.logger = logging.getLogger(__name__)
        os.environ["HGPLAIN"] = "1"
        self.lockfd = None
        if create:
            result = util.call2("hg init %s" % path)
            if result.returncode != 0:
                raise HgError("Failed to initialize repository! %s %s" % (result.out, result.err))
        self.root = Repo.get_root(path)
        # 'first' is usable as unique repository identification
        self.first_rev = self.get_rev_id('0')
        self.source_repo = self.get_source_repo().out

    def __del__(self):
        self.unlock()

    def _get_ssh_command(self):
        return "--ssh \"ssh -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oPasswordAuthentication=no\""

    def get_source_repo (self):
        cmd = ("hg -R %s path default" % self.root)
        return hgcmd(cmd)

    def get_rev_ids(self, rev=None, branch=None):
        cmd = "hg -q -R %s log --template '{node}\\n'" % self.root
        if rev != None:
            cmd += " -r \"%s\"" % rev
        if branch != None:
            cmd += " -r \"branch(%s)\"" % branch
        result = util.call2(cmd)
        if result.returncode == 0:
            changesets = result.out.split('\n')
            changesets = [changeset for changeset in changesets if changeset]
            return changesets
        elif result.returncode == 1: #No changesets
            return self._changesets('')
        else:
            raise HgError("Failed to get revision ids! %s %s %s" % (cmd, result.out, result.err))

    def get_rev_id(self, rev=None, branch=None):
        """get full revision for specified branch (head of branch), or for
        specified revision, or for current revision"""
        if branch != None:
            rev = branch
        elif rev == None:
            rev = '.'

        return self.get_rev_ids(rev, branch)[0]

    def get_branch(self, rev=None):
        cmd = "hg -q --hidden -R %s id -b" % self.root
        if rev != None:
            cmd += " -r %s" % rev
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError("Failed to get branch! %s %s %s" % (cmd, result.out, result.err))
        else:
            return result.out

    def get_parents(self, rev):
        cmd = "hg -q --hidden -R {repo} log --template \"{{parents % '{{node}} '}}\n\"".format(repo=self.root)
        cmd += " -r %s" % rev
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError("Failed to get parents! %s %s %s" % (cmd, result.out, result.err))
        else:
            return [x.strip() for x in result.out.split(' ')]

    def rebase(self, revs, dest, mergetool=None):
        cmd = "hg -R {repo} --hidden --config experimental.rebaseskipobsolete=false --config experimental.evolution=all --config extensions.rebase= rebase --tool internal:fail --dest {dest}".format(dest=dest, repo=self.root)
        for rev in revs:
            cmd += " -r {rev}".format(rev=rev)
        if mergetool:
            cmd += " --tool custommergetool --config merge-tools.custommergetool.executable=%s --config merge-tools.custommergetool.premerge=false" % mergetool
        res = util.call2(cmd)
        if res.returncode != 0:
            mergeconflicts = self.mergeconflicts().out
            if mergeconflicts:
                res.err += "\nMerge conflicts are:\n%s" % mergeconflicts
            util.call2("hg -R {repo} --config extensions.rebase= rebase --abort".format(repo=self.root))
        return res

    def _changesets(self, strings):
        changesets = []
        for line in strings:
            if line.find(' ') >= 0: #Not a changeset id (TODO: better check)
                continue
            if len(line.strip()) == 0: #Only whitespace
                continue
            changesets.append(line)
        return changesets

    def get_incoming_changesets(self, repo, rev=None, fields=["node"]):
        #--insecure: avoid popups requesting to check server key
        #-n: newest changesets first
        cmd = "hg incoming -q -R %s --insecure %s -n --template '{node}\\n' %s" % (self.root, self._get_ssh_command(), repo)
        if rev != None:
            cmd += " -r %s" % rev
        result = util.call2(cmd)
        if result.returncode == 0:
            changesets = result.out.split('\n')
            return self._changesets(changesets)
        elif result.returncode == 1: #No changesets
            return self._changesets('')
        else:
            raise HgError("Failed to get incoming changesets! %s %s %s" % (cmd, result.out, result.err))

    def incoming_new(self, repo, rev=None, fields=[]):
        """
            This is a new, more flexible implementation of 'incoming'.
        """
        SPLITTER = ":"
        wrapped_fields = []
        for field in fields:
            wrapped_fields.append("{%s}" % field)
        fields_output = SPLITTER.join(wrapped_fields)
        cmd = "hg incoming -q -R %s --insecure %s -n --template '%s\\n' %s" % (self.root, self._get_ssh_command(),
            fields_output, repo)
        if rev != None:
            cmd += " -r %s" % rev
        result = util.call2(cmd)
        if result.returncode == 0:
            changesets = result.out.split('\n')
            formatted_result = []
            for changeset in changesets:
                parts = changeset.split(SPLITTER)
                if len(parts) != len(fields):
                    continue #Incorrect changeset?
                changeset_result = {}
                for idx, field in enumerate(fields):
                    changeset_result[field] = parts[idx]
                formatted_result.append(changeset_result)
            return formatted_result
        elif result.returncode == 1:
            return []
        else:
            raise HgError("Failed to get incoming changesets! %s %s %s" % (cmd, result.out, result.err))

    def outgoing(self, repo, rev=None):
        cmd = "hg outgoing -R %s --insecure %s -q --template '{node}\\n' %s" % (self.root, self._get_ssh_command(), repo)
        if rev != None:
            cmd += " --rev %s" % rev
        result = util.call2(cmd)
        if result.returncode == 0:
            return self._changesets(result.out.split('\n'))
        elif result.returncode == 1:
            return self._changesets('')
        else:
            error = HgError("Failed to get outgoing changesets! %s %s" % (result.out, result.err))
            error.out = result.out
            error.err = result.err
            raise error

    def getRevs(self, revlist, fields):
        if not revlist:
            return '(none)'
        keys=[]
        sep='=+=+=+===+=+=+'
        fieldsep='%#$%^fieldsep&**&^%'
        template=[sep]
        for field in fields:
            key=field.split('=')
            keys.append(key[0])
            template.append(key[1])
        cmd = "hg log -R %s --template '%s' --rev %s" % (self.root, fieldsep.join(template),' --rev '.join(revlist))
        result = util.call2(cmd)
        if result.returncode == 0:
            revs=[]
            for rev,line in zip(revlist,result.out.split(sep)[1:]):
                values=line.split(fieldsep, len(fields))[1:]
                revs.append(Rev(rev,dict(list(zip(keys,values)))))
            return revs
        else:
            raise HgError("Failed to show overview of revisions: %s" % ' '.join(revlist))
        
    def revision_overview(self, revlist=[]):
        """Show an overview of the revisions specified"""
        if not revlist:
            return '(none)'

        cmd = "hg log -R %s --template '{node|short} {date|shortdate} {branch} {author|person} \t{desc|strip|firstline}\\n' --rev %s" % (self.root, ' --rev '.join(revlist))
        result = util.call2(cmd)
        if result.returncode == 0:
            return result.out
        else:
            raise HgError("Failed to show overview of revisions: %s" % ' '.join(revlist))

    def heads(self, branch=None, include_closed=True):
        #Specify '--closed' to show all the heads (closed ones as well)
        cmd = "hg -R %s heads " % self.root
        if include_closed:
            cmd += "--closed "
        cmd += "--template '{branch} {node}\n'"
        if branch != None:
            cmd += " %s" % branch
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError("Failed to get heads. %s %s %s" % (result.returncode, result.out, result.err))
        branch_heads = defaultdict(list)
        # create a list of all terms (branch node branch node ...)
        l = result.out.split()
        for branch, node in zip(l[::2], l[1::2]):
            branch_heads[branch].append(node)

        return dict(branch_heads)

    def strip(self, revisions=[]):
        changesets = self._changesets(revisions)
        if len(changesets) == 0:
            return True #Successful, but no changesets stripped
        revision_string = ' '.join(changesets)
        cmd = "hg -R %s --hidden --config extensions.strip= strip -f %s" % (self.root, revision_string)
        result = util.call2(cmd)
        self.logger.info("Strip command: %s" % cmd)
        self.logger.info("Strip result: %s, %s" % (result.out, result.err))
        return result.returncode == 0

    def pull(self, repo, rev=None, pbranch=None, extra_args=None):
        self.logger.info("pull %s %s" % (repo, rev))
        cmd = "hg -R %s --hidden pull --insecure %s %s" % (self.root, self._get_ssh_command(), repo)
        if rev != None:
            cmd += " -r %s" % rev
        if pbranch != None:
            cmd += " -b %s" % pbranch
        if extra_args:
            cmd += " %s" % extra_args
        return hgcmd(cmd)

    def push(self, repo, rev=None, force=False, branch=None):
        self.logger.info("push %s %s %s" % (repo, rev, force))
        cmd = "hg -R %s --config experimental.evolution=all push --insecure %s %s" % (self.root, self._get_ssh_command(), repo)
        if rev != None:
            cmd += " -r %s" % rev
        if force:
            cmd += " -f"
        if branch != None:
            cmd += " -b %s" % branch
        print("Push arguments: %s" % cmd)
        return hgcmd(cmd)

    def incoming(self, repo, rev=None):
        self.logger.info("incoming %s %s" % (repo, rev))
        cmd = "hg -R %s incoming --insecure %s %s" % (self.root, self._get_ssh_command(), repo)
        if rev != None:
            cmd += " -r %s" % rev
        return hgcmd(cmd)

    def update(self, rev=None, clean=True):
        self.logger.info("update %s %s" % (rev, clean))
        cmd = "hg -R %s update" % self.root
        if clean:
            cmd += " -C"
        if rev != None:
            cmd += " %s" % rev
        return hgcmd(cmd)

    def merge(self, rev=None):
        self.logger.info("merge %s" % rev)
        cmd = "HGMERGE=internal:fail hg -R %s merge" % self.root
        if rev != None:
            cmd += " -r %s" % rev
        self.logger.info("cmd: %s" % cmd)
        result = hgcmd(cmd)
        self.logger.info("result: %s" % result)
        if "use (c)hanged version or leave (d)eleted" in result.out:
            result.returncode = -1
        if "use (c)hanged version or (d)elete?" in result.out:
            result.returncode = -1
        return result

    def dummy_merge(self, rev=None):
        self.logger.info("dummy_merge %s" % rev)
        #First we do a regular merge
        result = self.merge(rev)
        if result.returncode > 1:
            return result
        #Then we revert all changes
        #So we ignore all changes coming from the other revision
        cmd = "hg -R %s revert --all --rev ." % self.root
        result = hgcmd(cmd)
        if result.returncode != 0:
            return result
        #Finally we say that all merge issues are resolved
        cmd = "hg -R %s resolve -a -m" % self.root
        result = hgcmd(cmd)
        return result

    def status(self, args=""):
        result = util.call2("hg -R %s status -q %s" % (self.root, args))
        if result.returncode != 0:
            raise HgError("Failed to check for uncommitted files. %s %s %s" % (cmd, result.out, result.err))
        else:
            return result.out

    def diff(self, args=""):
        cmd="hg -R %s diff %s" % (self.root, args)
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError("Failed to check for differences in files. [%s] [%s] [%s]" % (cmd, result.out, result.err))
        else:
            return result.out

    def changed_files(self, changesets_from="tip", changeset_to="tip"):
        if not isinstance(changesets_from, list):
            changesets_from = [changesets_from]

        cmd = "hg -R %s log --template '{files} '" % self.root
        for changeset_from in changesets_from:
            cmd += " --rev %s:%s" % (changeset_from, changeset_to)
        result = util.call2(cmd)
        if result.returncode == 0:
            return result.out.split(' ')
        else:
            return []

    def cat(self, revision, file_location):
        result = util.call2("hg -R %s cat -r %s %s" % (self.root, revision, file_location))
        if result.returncode != 0:
            raise HgError("Failed to cat file! %s" % result.out)
        else:
            return result.out

    def commit(self, message=None, user=None, extra_args=None):
        if message == None:
            message = ""
        cmd = "hg -R %s commit -m \"%s\"" % (self.root, message)

        if user != None:
            user = ' --user "%s"' % user
            cmd += user
        if extra_args:
            cmd += ' %s' % extra_args
        return hgcmd(cmd)

    def description(self, revision):
        result = util.call2("hg -R %s log -r %s --template {desc}" % (self.root, revision))
        if result.returncode != 0:
            raise HgError("Failed to get description of revision %s" % revision)
        else:
            return result.out

    def description_dict(self, revlist):
        result = util.call2("hg -R %s log --template NODE:{node}DESC:{desc} -r%s" % (self.root, " -r".join(revlist)))
        if result.returncode != 0:
            raise HgError("Failed to get description of revlist %s" % revlist)
        else:
            return self._parse_description_node_desc(result.out)

    def _parse_description_node_desc(self, text):
        rev_desc_dict = {}
        rev_desc_list = text.split("NODE:")
        for rev_desc in rev_desc_list:
            item_list = rev_desc.split("DESC:")
            if len(item_list) == 2:
                node = item_list[0]
                desc = item_list[1]
                rev_desc_dict[node] = desc
        return rev_desc_dict

    def author(self, revision):
        result = util.call2("hg -R %s log -r %s --template {author}" % (self.root, revision))
        if result.returncode != 0:
            raise HgError("Failed to get author of revision %s: %s %s" % (revision, result.out, result.err))
        else:
            return result.out

    def showconfig(self, key):
        result = util.call2("hg -R %s showconfig %s" % (self.root, key))
        if result.returncode != 0:
            raise HgError("Failed to get configuration for %s: %s, %s, %s" % (key, result.out, result.err, result.returncode))
        return result.out

    def mergeconflicts(self):
        return hgcmd("hg -R %s resolve -l" % self.root)
    
    def add(self, filename):
        result = util.call2("hg -R %s add %s" % (self.root, filename))
        if result.returncode != 0:
            raise HgError("Failed to add files: %s %s" % (result.out, result.err))
        else:
            return result.out

    def lock(self,type):
        if not self.lockfd:
            fd = os.open(os.path.join(self.root,'.hg/userLock'), os.O_RDWR | os.O_CREAT)
            self.lockfd=os.fdopen(fd, "w+")
        if type == 'w':
            fcntl.flock(self.lockfd,fcntl.LOCK_EX)
            self.lockfd.seek(0)
            self.lockfd.write("%d\n"%os.getpid())
            self.lockfd.truncate()
        else:
            fcntl.flock(self.lockfd,fcntl.LOCK_SH)

    def unlock(self):
        if self.lockfd:
            fcntl.flock(self.lockfd,fcntl.LOCK_UN)
            self.lockfd.close()
            self.lockfd=None

    def get_rebased_changesets(self, source_changesets=None):
        if not source_changesets:
            return []
        rebased_changesets = []
        rebased_change_cmd = []
        for source_changeset in source_changesets:
            rebased_change_cmd.append("extra(rebase_source, %s)" % source_changeset)
        cmd = "hg -R %s log -r \"%s\" --template '{node} '" % (self.root, ' or '.join(rebased_change_cmd))
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError("Failed to get rebased revisions")
        return (x.strip() for x in result.out.split(' '))

    def obsolete_revs(self, revisions=None):
        if not revisions:
            return []
        cmd = "hg -R %s log --hidden --template '{node}\n'" % (self.root)
        cmd += " --rev 'obsolete() and ("
        cmd += ' or '.join(revisions)
        cmd += ")'"
        result = util.call2(cmd)
        if result.returncode != 0:
            raise HgError(str(result))
        #Returning as list instead of as generator, to be able to use as bool
        res = [x.strip() for x in result.out.split('\n') if x.strip()]
        return res

    def stripobsolete(self, revisions=None, source_revisions=True):
        """Remove obsolete markers that make one of the given revisions obsolete.
           If source_revisions is false, remove obsolete markers that make 'revisions' successors of obsolete revisions"""
        if not revisions:
            return []
        cmd = "hg -R %s debugobsolete -Tjson --hidden --index" % self.root
        cmd += " --rev '%s'" % ' or '.join(revisions)
        result = util.call2(cmd)
        if result.returncode != 0:
            return result
        import json
        obsolete_markers = json.loads(result.out)
        indices_to_remove = set()
        for marker in obsolete_markers:
            if source_revisions:
                if ('precnode' in marker and marker["precnode"] in revisions) or ('prednode' in marker and marker["prednode"] in revisions):
                    indices_to_remove.add(marker["index"])
            else:
                for node in marker["succnodes"]:
                    if node in revisions:
                        indices_to_remove.add(marker["index"])
        if indices_to_remove:
            cmd = "hg -R %s debugobsolete %s" % (self.root, ' '.join(('--delete %s' % x for x in indices_to_remove)))
            result = util.call2(cmd)
            self.logger.info("Stripobsolete result: %s, %s" % (result.out, result.err))
        return result

if __name__ == "__main__":

    from optparse import OptionParser
    from sys import exit

    parser = OptionParser()
    parser.add_option("-r", "--rev", dest="revision", default=None,
                      help="Revision")
    parser.add_option("-R", dest="repository", default=".",
                      help="Repository location")
    parser.add_option("--remote", dest="remote", default=None,
                      help="Remote repository location")
    parser.add_option("--create", dest="create", default=False,
                      help="Create repository if necessary")
    parser.add_option("--clean", dest="clean", default=True)
    parser.add_option("--message", dest="message", default=None,
                      help="Commit message")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("No command given to execute.")
        exit(1)

    repo = Repo(options.repository, create=options.create)

    #TODO: use something else than a large if?
    if args[0] == 'pull':
        exit(repo.pull(options.remote, options.revision).returncode)
    elif args[0] == 'incoming':
        exit(repo.incoming(options.remote, options.revision).returncode)
    elif args[0] == 'update':
        exit(repo.update(rev=options.revision, clean=options.clean).returncode)
    elif args[0] == 'merge':
        exit(repo.merge(rev=options.revision).returncode)
    elif args[0] == 'commit':
        exit(repo.commit(message=options.message).returncode)
    elif args[0] == 'mergeconflicts':
        result = repo.mergeconflicts()
        print(result.out)
        exit(result.returncode)
    elif args[0] == 'stripoutgoing':
        # First delete the obsstore which contains all the obsolete markers (we will pull the published ones again from the central repository)
        obsstore_path = os.path.join(options.repository, '.hg', 'store', 'obsstore')
        if os.path.exists(obsstore_path):
            os.remove(obsstore_path)

        # Pull from the source repository
        sourcerepo = args[1]
        print(repo.pull(sourcerepo))
        outgoing = repo.outgoing(sourcerepo)
        print("Outgoing changesets: %s" % outgoing)
        if not outgoing:
            print("No outgoing changesets: done!")
            exit(0)
        print(repo.strip(outgoing))
        outgoing = repo.outgoing(sourcerepo)
        print("Outgoing changesets after strip: %s" % outgoing)
    elif args[0] == 'stripallobsoletemarkers':
        obsstore_path = os.path.join(options.repository, '.hg', 'store', 'obsstore')
        if os.path.exists(obsstore_path):
            os.remove(obsstore_path)
    else:
        print("Unimplemented.")
