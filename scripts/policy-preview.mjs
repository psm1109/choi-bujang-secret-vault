import { previewPolicy, restoreTrialPolicy } from '../src/policy-preview.mjs';

try {
  const args = process.argv.slice(2);
  const names = ['--backup', '--signature', '--trusted-key', '--before', '--trial-root', '--confirm'];
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    if (!names.includes(args[index]) || !args[index + 1] || options[args[index]]) throw new Error();
    options[args[index]] = args[index + 1];
  }
  if (names.slice(0, 5).some(name => !options[name])) throw new Error();
  const input = {
    backupPath: options['--backup'], signaturePath: options['--signature'],
    publicKeyPath: options['--trusted-key'], before: options['--before'],
    trialRoot: options['--trial-root'],
  };
  const result = options['--confirm']
    ? await restoreTrialPolicy(input, options['--confirm']) : await previewPolicy(input);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch {
  process.stderr.write('정책 절차 중단: 사본·검증·시험 사본 표시·미리보기 확인값을 확인하세요.\n');
  process.exitCode = 1;
}
