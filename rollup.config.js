import typescript from 'rollup-plugin-typescript2';

export default [
    {
        input: 'src/index.ts',
        output: {
            file: 'dist/bundle.js',
            format: 'cjs'
        },
        external: ['node-forge'],
        plugins: [typescript()]
    }
];
