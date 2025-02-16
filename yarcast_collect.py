import git
import os
import shutil
import stat
import yara
import plyara
import plyara.core as plycore
import plyara.utils as plyutils
import math
import re
import sys
import traceback

main_git_dir = "yara"
final_rules_dir = "yarafinal"
repo_filename = 'full_checkout_repos.csv'
sparse_repo_filename = 'sparse_checkout_repos.csv'
local_signature_folders = 'local_signature_folders.csv'
rule_hashes = []

def read_fully_clone_repos():
    result = {}
    if not os.path.exists(repo_filename):
        print("no full clone repos loaded")
        return result
    with open(repo_filename, 'r') as f:
        for line in f.readlines():
            if ',' in line:
                # split at first occurence of ','
                name, url = line.split(',', 1)
                result[name.strip()] = url.strip()
    return result

def read_sparse_checkout_repos():
    result = []
    if not os.path.exists(sparse_repo_filename):
        print("no sparse checkout repos loaded")
        return result
    with open(sparse_repo_filename, 'r') as f:
        for line in f.readlines():
            if ',' in line:
                # split at first and second occurence of ','
                name, url, folder_pieces = line.split(',', 2)
                # join the folders with OS specific separator
                folder = os.path.join(*folder_pieces.split(','))
                result.append((name.strip(), url.strip(), folder.strip()))
    return result

def read_local_signature_folders():
    result = {}
    if not os.path.exists(local_signature_folders):
        print("no local repos loaded")
        return result
    with open(local_signature_folders, 'r') as f:
        for line in f.readlines():
            if ',' in line:
                # split at first occurence of ','
                name, path = line.split(',', 1)
                result[name.strip()] = path.strip()
    return result

# repo_dir : repo_url
fully_clone_repos = read_fully_clone_repos()

# (repo_dir, repo_url, path)
sparse_checkout_repos = read_sparse_checkout_repos()

# repo_dir : local_path
local_signature_folders = read_local_signature_folders()

#def hook(l=None):
#	if l:
#		locals().update(l)
#		import IPython
#		IPython.embed(banner1='', confirm_exit=False)
#		exit(0)


def readfile(afile):
    with open(afile, 'r') as f:
        return f.read()
    
def write_rules(rules, outfile):
    for rule in rules:
        content = plyutils.rebuild_yara_rule(rule)
        compiled_rules = yara.compile(source=content)
        compiled_rules.save(outfile)


# len of a yara string in bytes
# ignores 'wide' because this does not improve the string in any way
# ignores wildcards and alternatives in byte patterns
# reduces regex to something sensible, ignoring special characters
def yara_str_len(str):
    if str['type'] == 'text':
        return len(str['value'])
    elif str['type'] == 'byte':
        raw = str['value']
        # no whitespace and braces
        s = re.sub(r"\s+", '', raw)[1:-1]
        # no wildcards or alternatives
        s = re.sub(r"(\?|\[.*?\]|\(.*?\))", '', s)
        result = math.floor(len(s) / 2)
        return result
    elif str['type'] == 'regex':
        raw = str['value']
        # no /
        s = raw[1:-1]
        # no wildcards or special symbols or alternatives
        s = re.sub(r"(\{.*?\}|\[.*?\]|\(.*?\))", '', s)
         # no special chars
        s = re.sub(r"[^\\]([\?\+\.\*\^]+)", '', s)
        # reduce \xAB to one char
        s = re.sub(r"\\x\d\d", 'b', s)
        # remove \w \W \d \D \s \S etc
        s = re.sub(r"[^\\](\\)[^\\]", '', s)
        # \\ --> 1
        s = re.sub(r"\\\\", "1", s)
        result = len(s)
        return result
    sys.stderr.write("something went wrong determining the string type\n")
    return None

def has_too_short_strings(rule):
    str_list = rule.get('strings', [])
    for str in str_list:
        length = yara_str_len(str)
        if length != None and length < 4:
            return True
    return False

def filter_applicable_rules(rules, verbose=False):
    global rule_hashes
    applicable = []
    too_short = 0
    duplicates = 0
    blocklist = load_blocklist()
    for rule in rules:
        rule_hash = plyutils.generate_hash(rule)
        if rule['rule_name'] in blocklist:
            if verbose: print(rule['rule_name'], 'is in blocklist, skipped')
        elif rule_hash in rule_hashes:
            duplicates += 1
            if verbose: print(rule['rule_name'], 'is a duplicate, skipped')
        elif has_too_short_strings(rule):
            too_short += 1
            if verbose: print(rule['rule_name'], 'has too short strings, skipped')
        else:
            applicable.append(rule)
        rule_hashes.append(rule_hash)
    return (applicable, too_short, duplicates)

def is_compileable(sigfile, verbose=False):
    try:
        yara.compile(filepath=sigfile)
        return True
    except Exception as e:
        if verbose: print('cannot compile', sigfile, 'reason', e)
        return False
        
def collect_applicable_rules(local_path, verbose=False):
    rules_added_total = 0
    duplicates_total = 0
    short_patterns_total = 0
    sigfiles_filtered = 0
    print('processing', local_path)
    repo = os.path.join(main_git_dir, local_path)
    # create output directory
    outdir = os.path.join(final_rules_dir, local_path)
    if not os.path.exists(outdir): os.mkdir(outdir)
    for subdir, dirs, files in os.walk(repo):
        for file in files:
            sigfile = os.path.join(subdir, file)
            if not is_compileable(sigfile, verbose):
                sigfiles_filtered += 1
                continue
            if verbose: print('found', sigfile)
            try:
                file_content = readfile(sigfile)
                parser = plyara.Plyara(import_effects=True)
                rules = parser.parse_string(file_content)
                applicable_rules, too_short, duplicates = filter_applicable_rules(rules, verbose)
                short_patterns_total += too_short
                duplicates_total += duplicates
                outfile = os.path.join(outdir, file)

                write_rules(applicable_rules, outfile)
                rules_added_total += len(applicable_rules)
                if verbose: print('filtered', (too_short + duplicates) ,'rules, result written to', outfile)
            except Exception as e:
                if verbose: 
                    print('compile or read error:', sigfile, 'this file will be skipped')
                    print(traceback.format_exc())
    print("rules filtered (short patterns):", short_patterns_total)
    print("rules filtered (duplicates):", duplicates_total)
    print("rules added:", rules_added_total)
    print("files filtered (not compilable):", sigfiles_filtered)
    print()
    return rules_added_total

def get_all_yara_pathes():
    path_list = [os.path.join(main_git_dir, name) for name, url in fully_clone_repos.items()]
    path_list += [os.path.join(main_git_dir, name, folder) for name, url, folder in sparse_checkout_repos]
    return path_list
    
def sparse_checkout_repository(repo_url, local_path, sparse_checkout_folder):
    full_path = os.path.join(main_git_dir, local_path)
    repo_name = local_path
    if os.path.exists(full_path) and is_git_repository(full_path):
        # Repository exists, pull to update
        branch_name = "master"
        repo = git.Repo(full_path)
        print(f"Repository at {full_path} already exists. Pulling updates...")
        repo.remotes[repo_name].pull(branch_name)
    else:
        # Clone the repository
        repo = git.Repo.clone_from(repo_url, full_path, quiet=True)
        print(f"Repository cloned to {repo.working_dir}")

        # Remove the .git folder
        delete_folder(os.path.join(full_path, '.git'))

        # Initialize a new Git repository
        repo = git.Repo.init(full_path)
        print("Git repository initialized")

        # Add a remote and fetch
        repo.create_remote(repo_name, repo_url)
        repo.remotes[repo_name].fetch()

        # Configure sparse checkout
        os.makedirs(os.path.join(full_path, '.git/info'), exist_ok=True)
        with open(os.path.join(full_path, '.git/info/sparse-checkout'), 'w') as sparse_checkout_file:
            sparse_checkout_file.write(sparse_checkout_folder)

        repo.config_writer().set_value('core', 'sparseCheckout', 'true').release()
        repo.config_writer().set_value('pull', 'rebase', 'false').release()

        # Pull the specific folder from the remote
        repo.index.checkout(force=True)
        print(f"Sparse checkout configured, and folder {sparse_checkout_folder} pulled")

def save_total_rules_to_file(total_rules):
    filename = 'total_rules.txt'
    if os.path.exists(filename):
        os.remove(filename)
    with open(filename, 'w') as f:
        f.write(str(total_rules))

def load_blocklist():
    """Loads the blocklist"""
    block_file = 'blocklist.txt'
    if not os.path.exists(block_file):
        return []
    with open(block_file, 'r') as f:
        return f.read().splitlines()

def is_git_repository(path):
    try:
        git.Repo(path).git_dir
        return True
    except git.InvalidGitRepositoryError:
        return False

def clone_or_pull_repository(repo_url, local_path):
    full_path = os.path.join(main_git_dir, local_path)

    if os.path.exists(full_path) and is_git_repository(full_path):
        # Repository exists, pull to update
        repo = git.Repo(full_path)
        print(f"Repository at {full_path} already exists. Pulling updates...")
        repo.remotes.origin.pull()
    else:
        # Repository does not exist, clone it
        repo = git.Repo.clone_from(repo_url, full_path, quiet=True)
        print(f"Repository cloned to {repo.working_dir}")
        
def delete_repository(local_path):
    full_path = os.path.join(main_git_dir, local_path)
    delete_folder(full_path)

def delete_folder(full_path, verbose=False):
    def remove_readonly(func, path, _):
        "Clear the readonly bit and reattempt the removal"
        #try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
        #except:
        #    sys.stderr.write("something went wrong with deletion of " + path)
    
    if os.path.exists(full_path):
        # Delete the existing repository
        shutil.rmtree(full_path, onexc=remove_readonly)
        if verbose: print(f"Folder at {full_path} deleted.")
    else:
        if verbose: print(f"Folder at {full_path} does not exist.")

def delete_all_repos():
    for local_path, _ in fully_clone_repos.items():
        delete_repository(local_path)
    for local_path, _, _ in sparse_checkout_repos:
        delete_repository(local_path)

def copy_files_to_local_repo(local_path, repo_dir):
    print(f"Loading local repository {repo_dir}")
    full_path = os.path.join(main_git_dir, local_path)
    if not os.path.exists(full_path):
        os.mkdir(full_path)
    for root, _, files in os.walk(repo_dir):
        for file in files:
            shutil.copy(os.path.join(root, file), full_path)

# collect all yara rules from all public repos 
def collect():
    failed_repos = {}
    delete_folder(final_rules_dir)
    os.mkdir(final_rules_dir)
    total_rules = 0
    for local_path, repo_url in fully_clone_repos.items():
        try:
            clone_or_pull_repository(repo_url, local_path)
            rules_num = collect_applicable_rules(local_path)
            if rules_num == 0: failed_repos[repo_url] = f"no rules added for local path {local_path}"
            total_rules += rules_num
        except git.exc.GitCommandError as e:
            print(f"GitCommandError: {e}")
            print(f"Failed to clone or update the repository {repo_url}")
            failed_repos[repo_url] = f"failed to clone or update - GitCommandError {e}"
        except Exception as e:
            print(f"Exception: {e}")
            print(f"Failed to clone or update the repository {repo_url}")
            failed_repos.append(repo_url)
    for local_path, repo_url, folder in sparse_checkout_repos:
        try:
            sparse_checkout_repository(repo_url, local_path, folder)
            rules_num = collect_applicable_rules(local_path)
            if rules_num == 0: failed_repos[repo_url] = f"no rules added for local path {local_path}"
            total_rules += rules_num
        except git.exc.GitCommandError as e:
            print(f"Error: {e}")
            print(f"Failed to clone or update the repository {repo_url}")
            failed_repos[repo_url] = f"failed to clone or update - GitCommandError {e}"
        except Exception as e:
            print(f"Exception: {e}")
            print(f"Failed to clone or update the repository {repo_url}")
            failed_repos[repo_url] = f"failed to clone or update - Exception {e}"
    for local_path, repo_dir in local_signature_folders.items():
            copy_files_to_local_repo(local_path, repo_dir)
            rules_num = collect_applicable_rules(local_path)
            if rules_num == 0: failed_repos[repo_url] = f"no rules added for local path {local_path}"
            total_rules += rules_num
    save_total_rules_to_file(total_rules)
    print('-------------------')  
    print('total rules added:', total_rules)
    print('repos checked:', len(fully_clone_repos) + len(sparse_checkout_repos))
    
    if(len(failed_repos) == 0):
        print('failed repos: 0')
    else:
        print('failed repos:')
        for repo, reason in failed_repos.items():
            print(repo, ":", reason)
        
if __name__ == "__main__":
    delete_all_repos()
    collect()
    delete_all_repos()