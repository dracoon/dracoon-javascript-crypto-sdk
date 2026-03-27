import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';

/**
 * `rollup-plugin-typescript2` breaks when being used with `picomatch` 2.3.2,
 * so we set the include option manually until a fix is released for that.
 * @see https://github.com/ezolenko/rollup-plugin-typescript2/issues/480
 */
const include = ['*.ts{,x}', '**/*.ts{,x}', '**/*.cts', '**/*.mts'];

export default [
    {
        input: 'src/index.default.ts',
        output: {
            file: 'lib/browser/cjs/bundle.js',
            format: 'cjs'
        },
        external: ['node-forge'],
        plugins: [typescript({ useTsconfigDeclarationDir: true, include })]
    },
    {
        input: 'src/index.node.ts',
        output: {
            file: 'lib/node/cjs/bundle.js',
            format: 'cjs'
        },
        external: ['crypto'],
        plugins: [commonjs(), nodeResolve(), typescript({ useTsconfigDeclarationDir: true, include })]
    }
];
