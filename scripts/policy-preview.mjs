import { previewPolicy } from '../src/policy-preview.mjs';

try {
  const args = process.argv.slice(2);
  const names = ['--backup', '--signature', '--trusted-key', '--before', '--trial-root'];
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    if (!names.includes(args[index]) || !args[index + 1] || options[args[index]]) throw new Error();
    options[args[index]] = args[index + 1];
  }
  if (Object.keys(options).length !== names.length) throw new Error();
  const result = await previewPolicy({
    backupPath: options['--backup'], signaturePath: options['--signature'],
    publicKeyPath: options['--trusted-key'], before: options['--before'],
    trialRoot: options['--trial-root'],
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch {
  process.stderr.write('정책 미리보기 중단: 사본·신뢰 공개키·서명·침해 전 검증 정보를 확인하세요.\n');
  process.exitCode = 1;
}
