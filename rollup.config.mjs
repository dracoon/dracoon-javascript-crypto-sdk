import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';

export default [
    {
        input: 'src/index.default.ts',
        output: {
            file: 'lib/browser/cjs/bundle.js',
            format: 'cjs'
        },
        external: ['node-forge'],
        plugins: [typescript({ useTsconfigDeclarationDir: true })]
    },
    {
        input: 'src/index.node.ts',
        output: {
            file: 'lib/node/cjs/bundle.js',
            format: 'cjs'
        },
        external: ['crypto'],
        plugins: [commonjs(), nodeResolve(), typescript({ useTsconfigDeclarationDir: true })]
    }
];
