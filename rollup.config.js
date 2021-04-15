import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';

export default [
    {
        input: 'src/index.ts',
        output: {
            file: 'lib/bundle.js',
            format: 'cjs'
        },
        external: ['node-forge'],
        plugins: [typescript()]
    },
    {
        input: 'src/index.ts',
        output: {
            file: 'dist/bundle.js',
            format: 'iife',
            name: 'Dracoon'
        },
        plugins: [commonjs(), nodeResolve({ browser: true }), typescript({ tsconfigOverride: { compilerOptions: { declaration: false } } })]
    }
];
