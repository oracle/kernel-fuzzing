import errno
import logging
import os
import pipes
import shutil
import subprocess
import tempfile

import jinja2
import yaml

HERE = os.path.abspath(os.path.dirname(__file__))

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def git_export(git_dir, rev, path):
    archive = subprocess.Popen([
        'git', '--git-dir=' + git_dir,
        'archive', '--format=tar',
        rev,
    ], stdout=subprocess.PIPE)
    subprocess.check_call(['tar', 'x'], cwd=path, stdin=archive.stdout)
    archive.wait()

CONFIG_PATH = os.path.join(HERE, '..', 'config.yml')

with open(CONFIG_PATH) as f:
    config = yaml.load(f)

def make(path, args):
    env = os.environ.copy()

    gcc5_path = config.get('gcc5_path')
    if gcc5_path:
        PATH = env['PATH']
        env['PATH'] = gcc5_path + ':' + PATH

    cc_args = []
    cc = config.get('cc')
    if cc:
        cc_args.append('CC=' + cc)

    subprocess.check_call(['make'] + cc_args + args, cwd=path, env=env)

TEMPLATES_DIR = os.path.join(HERE, '..', 'templates')

template_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES_DIR))
guest_init_template = template_env.get_template('init')

INCLUDE_DIR = os.path.join(HERE, '..', 'include')
SRC_DIR = os.path.join(HERE, '..', 'src')

class Fuzzer(object):
    def __init__(self, name, path):
        self.name = name
        self.path = path

        with open(os.path.join(path, 'config.yml')) as f:
            self.config = yaml.load(f)

    def build_so(self, cwd=None):
        subprocess.check_call([
            'g++', '-Wall',
            '-I' + INCLUDE_DIR,
            '-fpic', '-shared',
            '-o', self.name + '.so',
            os.path.join(SRC_DIR, 'afl-wrapper.cc'),
            os.path.join(self.path, self.name + '.cc'),
        ], cwd=(cwd or self.path))

    def build_exe(self, cwd=None):
        subprocess.check_call([
            'g++', '-Wall',
            '-I' + INCLUDE_DIR,
            '-o', self.name + '.exe',
            os.path.join(SRC_DIR, 'standalone.cc'),
            os.path.join(self.path, self.name + '.cc'),
        ], cwd=(cwd or self.path))

FUZZERS_DIR = os.path.join(HERE, '..', 'fuzzers')

all_fuzzers = {}
for name in os.listdir(FUZZERS_DIR):
    all_fuzzers[name] = Fuzzer(name, os.path.join(FUZZERS_DIR, name))

def write_init(path, vm, commands):
    with open(path, 'w') as f:
        print >>f, guest_init_template.render({
            'vm': vm,
            'commands': [' '.join([pipes.quote(arg) for arg in args]) for args in commands],
        })

    os.chmod(path, 0755)

def instrument(path):
    assert path.endswith('.o') or path.endswith('/')

    if path.endswith('.o'):
        dirname, basename = os.path.split(path)
        makefile_path = os.path.join(dirname, 'Makefile')

        logging.debug("Adding instrumentation to %s", makefile_path)
        with open(makefile_path, 'a') as f:
            print >>f
            print >>f, '# Instrumentation for AFL'
            print >>f, 'CFLAGS_%s += $(FUZZ_INSTRUMENT_PLUGIN_CFLAGS)' % basename

    if path.endswith('/'):
        makefile_path = os.path.join(path, 'Makefile')

        logging.debug("Adding instrumentation to %s", makefile_path)
        with open(makefile_path, 'a') as f:
            print >>f
            print >>f, '# Instrumentation for AFL'
            print >>f, 'subdir-ccflags-y += $(FUZZ_INSTRUMENT_PLUGIN_CFLAGS)'

CONFIG_DIR = os.path.join(HERE, '..')

class KernelBuilder(object):
    def __init__(self, config, fuzzer, vm):
        self.repo = config['linux_repo']
        self.rev = config['linux_afl_rev']

        self.fuzzer = fuzzer
        self.makefiles = fuzzer.config['instrument']

        self.vm = vm

    def write_config(self, config_path):
        with open(config_path, 'w') as fout:
            # First write the common part
            with open(os.path.join(CONFIG_DIR, 'satconfig.common')) as fin:
                fout.write(fin.read())

            # Then write the VM-specific part
            with open(os.path.join(CONFIG_DIR, 'satconfig.' + self.vm)) as fin:
                fout.write(fin.read())

            for var, value in self.fuzzer.config.get('config').iteritems():
                print >>fout, 'CONFIG_%s=%s' % (var, value)

    def make(self, path, args):
        vm_args = []
        if self.vm == 'uml':
            vm_args.append('ARCH=um')

        make(path, vm_args + args)

    def build(self, output_dir=None, config=None):
        output_dir = output_dir or self.fuzzer.path

        tmpdir = tempfile.mkdtemp()
        try:
            logging.debug("Building kernel in %s", tmpdir)

            git_export(self.repo, self.rev, tmpdir)
            for makefile in self.makefiles:
                instrument(os.path.join(tmpdir, makefile))

            if config:
                shutil.copyfile(config, os.path.join(tmpdir, '.config'))
            else:
                self.write_config(os.path.join(tmpdir, '.satconfig'))

                self.make(tmpdir, ['satconfig'])
                self.make(tmpdir, ['silentoldconfig'])

                # Copy back the generated config as a fallback
                shutil.copyfile(os.path.join(tmpdir, '.config'),
                    os.path.join(output_dir, 'config.' + self.vm))

            self.make(tmpdir, ['-j4'])
            shutil.copy(os.path.join(tmpdir, 'vmlinux'),
                os.path.join(output_dir, 'vmlinux.' + self.vm))

            if self.vm == 'kvm':
                shutil.copy(os.path.join(tmpdir, 'arch', 'x86', 'boot', 'bzImage'),
                    os.path.join(output_dir, 'bzImage.' + self.vm))
        except:
            raise
        finally:
            logging.info("Cleaning up temporary directory %s", tmpdir)
            shutil.rmtree(tmpdir)

        self.build_location = tmpdir

class AFLBuilder(object):
    def __init__(self, config, fuzzer):
        self.repo = config['afl_repo']
        self.rev = config['afl_rev']

        self.fuzzer = fuzzer

    def build(self):
        tmpdir = tempfile.mkdtemp()
        try:
            logging.debug("Building AFL in %s", tmpdir)

            git_export(self.repo, self.rev, tmpdir)
            subprocess.check_call(['make'], cwd=tmpdir)
            shutil.copy(os.path.join(tmpdir, 'afl-fuzz'), self.fuzzer.path)
        except:
            raise
        finally:
            shutil.rmtree(tmpdir)

class TerminalSaver(object):
    def __init__(self):
        pass

    def __enter__(self):
        self.stty = subprocess.check_output(['stty', '-g']).splitlines()[0]

    def __exit__(self, type, value, traceback):
        subprocess.check_call(['stty', self.stty])
        subprocess.check_call(['setterm', '-cursor', 'on'])
